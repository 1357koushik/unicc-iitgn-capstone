"""
The retrieval service's data bundle: everything the Team 2 retrieval service reads, in ONE folder.

The service does not build its indexes when it starts; it reads finished builds (about 8 GB). The
Docker container gets them as this folder, mounted read-only at /data:

    retrieval-data/
        BUNDLE.json                    what is inside: build IDs, size and sha256 of every file
        store/LATEST, store/<build>/           C1 CVE store (store.sqlite)
        lexical/LATEST, lexical/<build>/       C2 keyword index (lexical.sqlite + BM25 score matrix)
        dense/LATEST, dense/<build>/           C3 vector index (vectors.npy, read into RAM at start)
        attack/LATEST, attack/<build>/         C9 MITRE ATT&CK graph (attack.sqlite)
        techniques/LATEST, techniques/<build>/ ATT&CK technique ranking (optional)
        models/<model>/                        the query encoders (bge-large-en-v1.5, Qwen3-Embedding-0.6B)

Commands (run from the project folder):

  Make a bundle from existing builds (each folder is a build, or a folder whose LATEST names one):
    python scripts/docker/retrieval_data.py pack --out retrieval-data \\
        --store data/store --lexical data/lexical --dense data/dense --attack data/attack \\
        --techniques data/techniques --models data/models [--link]

  Check a bundle (the container runs the quick check at every start):
    python scripts/docker/retrieval_data.py check retrieval-data          # structure and sizes (seconds)
    python scripts/docker/retrieval_data.py check retrieval-data --full   # also every sha256 (about a minute)

Only the standard library is used, so it runs anywhere Python 3.9+ runs (no project packages needed).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

BUNDLE_FILE = "BUNDLE.json"
BUNDLE_FORMAT = "retrieval-data-1"

# The files each build must contain. Names follow the build code in threat_retrieval_engine/.
COMPONENTS = {
    "store": {"required": True, "files": ["manifest.json", "store.sqlite"]},
    "lexical": {"required": True, "files": ["manifest.json", "lexical.sqlite", "impact_data.npy",
                                            "impact_indices.npy", "impact_indptr.npy", "impact_rowids.npy"]},
    "dense": {"required": True, "files": ["manifest.json", "vectors.npy", "doc_ids.txt"]},
    "attack": {"required": True, "files": ["manifest.json", "attack.sqlite"]},
    "techniques": {"required": False, "files": ["manifest.json", "entries.jsonl"]},
}

# Technique-ranking encoders: name -> model folder (as threat_retrieval_engine/v2/techniques.py ENCODERS).
TECHNIQUE_ENCODERS = {
    "bge-large": "bge-large-en-v1.5",
    "sentsecbert": "SentSecBert_10k",
    "securebert2": "SecureBERT2.0-biencoder",
    "qwen3-emb": "Qwen3-Embedding-0.6B",
}
DEFAULT_TECHNIQUE_ENCODERS = ("bge-large", "qwen3-emb")   # = techniques.DEFAULT_ENCODERS
MODEL_WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin")


class BundleError(Exception):
    pass


# ----------------------------------------------------------------------------------------- helpers
def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise BundleError(f"cannot read {path}: {e}")


def resolve_build(path: Path) -> Path:
    """A build folder itself (it has manifest.json), or the build named by <path>/LATEST."""
    path = Path(path)
    if (path / "manifest.json").is_file():
        return path
    latest = path / "LATEST"
    if latest.is_file():
        build = path / latest.read_text(encoding="utf-8").strip()
        if (build / "manifest.json").is_file():
            return build
        raise BundleError(f"{latest} names '{build.name}', but {build} has no manifest.json")
    raise BundleError(f"no build found at {path} (expected a build folder with manifest.json, "
                      f"or a folder with a LATEST file naming one)")


def technique_encoders() -> list:
    raw = os.environ.get("TRE_TECH_ENCODERS", "").strip()
    names = [e for e in raw.split(",") if e] if raw else list(DEFAULT_TECHNIQUE_ENCODERS)
    unknown = [n for n in names if n not in TECHNIQUE_ENCODERS]
    if unknown:
        raise BundleError(f"unknown technique encoder(s) in TRE_TECH_ENCODERS: {', '.join(unknown)}")
    return names


def needed_models(builds: dict) -> list:
    """Model folders the service loads: the dense index's query encoder, plus the technique encoders."""
    dense_manifest = _read_json(builds["dense"] / "manifest.json")
    names = [dense_manifest.get("model", {}).get("name")]
    if not names[0]:
        raise BundleError(f"{builds['dense'] / 'manifest.json'} does not name its embedding model")
    if "techniques" in builds:
        names += [TECHNIQUE_ENCODERS[e] for e in technique_encoders()]
    return list(dict.fromkeys(names))


def _model_problems(folder: Path) -> list:
    if not folder.is_dir():
        return [f"model folder {folder} is missing"]
    problems = []
    if not (folder / "config.json").is_file():
        problems.append(f"{folder} has no config.json")
    if not any((folder / w).is_file() for w in MODEL_WEIGHT_FILES):
        problems.append(f"{folder} has no model weights ({' or '.join(MODEL_WEIGHT_FILES)})")
    return problems


def _consistency_problems(builds: dict) -> list:
    """The builds must have been made from each other (a mismatch gives wrong or failing searches)."""
    problems = []
    store_id = builds["store"].name
    lex = _read_json(builds["lexical"] / "manifest.json")
    for item in lex.get("inputs", []):
        if item.get("kind") == "cve" and item.get("store_build_id") not in (None, store_id):
            problems.append(f"lexical build {builds['lexical'].name} was made from store {item['store_build_id']}, "
                            f"not from store {store_id}")
    dense = _read_json(builds["dense"] / "manifest.json").get("inputs", {})
    if dense.get("store", {}).get("build_id") not in (None, store_id):
        problems.append(f"dense build {builds['dense'].name} was made from store {dense['store']['build_id']}, "
                        f"not from store {store_id}")
    attack_id = builds["attack"].name
    if dense.get("attack", {}).get("build_id") not in (None, attack_id):
        problems.append(f"dense build {builds['dense'].name} was made from ATT&CK build "
                        f"{dense['attack']['build_id']}, not from {attack_id}")
    if "techniques" in builds:
        tech = _read_json(builds["techniques"] / "manifest.json")
        if tech.get("attack_build") not in (None, attack_id):
            problems.append(f"techniques build {builds['techniques'].name} was made from ATT&CK build "
                            f"{tech['attack_build']}, not from {attack_id}")
    return problems


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _files_under(root: Path) -> list:
    return sorted(p for p in root.rglob("*") if p.is_file())


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} GB"


# ----------------------------------------------------------------------------------------- pack
def _copy_tree(src: Path, dst: Path, link: bool) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for f in _files_under(src):
        target = dst / f.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.stat().st_size == f.stat().st_size:
                continue                      # already there (re-run); sha256 is checked below
            target.unlink()
        if link:
            try:
                os.link(f, target)
                continue
            except OSError:
                pass                          # other disk: copy instead
        shutil.copy2(f, target)


def pack(out: Path, sources: dict, models_dir: Path, link: bool = False) -> dict:
    out = Path(out)
    builds = {}
    for name, spec in COMPONENTS.items():
        src = sources.get(name)
        if src is None:
            if spec["required"]:
                raise BundleError(f"--{name} is required")
            continue
        builds[name] = resolve_build(Path(src))
        missing = [f for f in spec["files"] if not (builds[name] / f).is_file()]
        if name == "techniques":
            missing += [f"emb_{e}.npy" for e in technique_encoders() if not (builds[name] / f"emb_{e}.npy").is_file()]
        if missing:
            raise BundleError(f"{name} build {builds[name]} lacks: {', '.join(missing)}")
    problems = _consistency_problems(builds)
    models = needed_models(builds)
    for m in models:
        problems += _model_problems(Path(models_dir) / m)
    if problems:
        raise BundleError("cannot pack:\n  - " + "\n  - ".join(problems))

    out.mkdir(parents=True, exist_ok=True)
    record = {"format": BUNDLE_FORMAT, "created_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "components": {}, "models": {}}
    for name, build in builds.items():
        print(f"[pack] {name}: {build.name}")
        _copy_tree(build, out / name / build.name, link)
        (out / name / "LATEST").write_text(build.name + "\n", encoding="utf-8")
        record["components"][name] = {"build_id": build.name, "files": _file_record(out / name / build.name)}
    for m in models:
        print(f"[pack] model: {m}")
        _copy_tree(Path(models_dir) / m, out / "models" / m, link)
        record["models"][m] = {"files": _file_record(out / "models" / m)}
    damaged = _manifest_checksum_problems(record, _read_json(builds["dense"] / "manifest.json"))
    if damaged:
        raise BundleError("the copied files do not match the build's own checksums:\n  - " + "\n  - ".join(damaged))
    total = sum(f["bytes"] for part in list(record["components"].values()) + list(record["models"].values())
                for f in part["files"].values())
    record["total_bytes"] = total
    (out / BUNDLE_FILE).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"[pack] done: {out} ({_human(total)}); {BUNDLE_FILE} written")
    return record


def _manifest_checksum_problems(record: dict, dense_manifest: dict) -> list:
    """The dense build lists the sha256 of its files and of its encoder's weights: compare."""
    problems = []
    dense_files = record["components"]["dense"]["files"]
    for name, sha in (dense_manifest.get("files") or {}).items():
        if name in dense_files and dense_files[name]["sha256"] != sha:
            problems.append(f"dense {name}: sha256 differs from the dense manifest")
    model = dense_manifest.get("model", {})
    weights = record["models"].get(model.get("name"), {}).get("files", {}).get(model.get("weights_file", ""))
    if weights and model.get("weights_sha256") and weights["sha256"] != model["weights_sha256"]:
        problems.append(f"model {model['name']}: weights differ from the ones the index was built with")
    return problems


def _file_record(root: Path) -> dict:
    return {f.relative_to(root).as_posix(): {"bytes": f.stat().st_size, "sha256": _sha256(f)} for f in _files_under(root)}


# ----------------------------------------------------------------------------------------- check
def check(root: Path, full: bool = False, techniques: bool = True) -> dict:
    """
    Check a bundle. Returns {"ok", "problems", "warnings", "builds", "models", "techniques"}.

    techniques=False: the technique ranking is not wanted, so its build and models are not required.
    """
    root = Path(root)
    problems, warnings, builds = [], [], {}
    if not root.is_dir():
        return {"ok": False, "problems": [f"the data folder {root} does not exist"], "warnings": [],
                "builds": {}, "models": [], "techniques": False}
    for name, spec in COMPONENTS.items():
        if name == "techniques" and not techniques:
            continue
        folder = root / name
        if not folder.exists():
            if spec["required"]:
                problems.append(f"{folder} is missing")
            else:
                warnings.append(f"{folder} is missing: ATT&CK technique ranking is off")
            continue
        try:
            build = resolve_build(folder)
        except BundleError as e:
            (problems if spec["required"] else warnings).append(str(e))
            continue
        missing = [f for f in spec["files"] if not (build / f).is_file()]
        if name == "techniques":
            try:
                missing += [f"emb_{e}.npy" for e in technique_encoders() if not (build / f"emb_{e}.npy").is_file()]
            except BundleError as e:
                missing.append(str(e))
        if missing:
            problems.append(f"{name} build {build} lacks: {', '.join(missing)}")
            continue
        builds[name] = build
    models = []
    if not problems:
        try:
            problems += _consistency_problems(builds)
            models = needed_models(builds)
            for m in models:
                problems += _model_problems(root / "models" / m)
        except BundleError as e:
            problems.append(str(e))

    record_path = root / BUNDLE_FILE
    if not record_path.is_file():
        warnings.append(f"no {BUNDLE_FILE}: file sizes and checksums cannot be checked "
                        f"(make the folder with the 'pack' command to get one)")
    elif not problems:
        try:
            problems += _check_files(root, _read_json(record_path), builds, models, full)
        except BundleError as e:
            problems.append(str(e))
    return {"ok": not problems, "problems": problems, "warnings": warnings,
            "builds": {k: v.name for k, v in builds.items()}, "models": models, "techniques": "techniques" in builds}


def _check_files(root: Path, record: dict, builds: dict, models: list, full: bool) -> list:
    if record.get("format") != BUNDLE_FORMAT:
        return [f"{BUNDLE_FILE} has format {record.get('format')!r}, expected {BUNDLE_FORMAT!r}"]
    problems = []
    parts = [(f"{name} build {build.name}", build, record.get("components", {}).get(name))
             for name, build in builds.items()]
    parts += [(f"model {m}", root / "models" / m, record.get("models", {}).get(m)) for m in models]
    for label, folder, entry in parts:
        if entry is None:
            problems.append(f"{label} is not listed in {BUNDLE_FILE}")
            continue
        if "build_id" in entry and entry["build_id"] != folder.name:
            problems.append(f"{label}: LATEST names {folder.name}, {BUNDLE_FILE} lists {entry['build_id']}")
            continue
        for rel, info in entry["files"].items():
            f = folder / rel
            if not f.is_file():
                problems.append(f"{label}: {rel} is missing")
            elif f.stat().st_size != info["bytes"]:
                problems.append(f"{label}: {rel} has {f.stat().st_size} bytes, expected {info['bytes']} "
                                f"(incomplete copy?)")
            elif full and _sha256(f) != info["sha256"]:
                problems.append(f"{label}: {rel} is damaged (sha256 differs)")
    return problems


# ----------------------------------------------------------------------------------------- command line
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pack", help="make a bundle from existing builds")
    p.add_argument("--out", required=True, type=Path)
    for name, spec in COMPONENTS.items():
        p.add_argument(f"--{name}", type=Path, required=spec["required"])
    p.add_argument("--models", required=True, type=Path, help="folder holding the model folders")
    p.add_argument("--link", action="store_true", help="hard-link files instead of copying (same disk only)")
    c = sub.add_parser("check", help="check a bundle")
    c.add_argument("root", nargs="?", type=Path, default=Path("retrieval-data"))
    c.add_argument("--full", action="store_true", help="also compare every file's sha256")
    c.add_argument("--no-techniques", action="store_true", help="the technique ranking is not wanted")
    args = ap.parse_args(argv)

    if args.command == "pack":
        try:
            pack(args.out, {n: getattr(args, n) for n in COMPONENTS}, args.models, link=args.link)
        except BundleError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0

    result = check(args.root, full=args.full, techniques=not args.no_techniques)
    for w in result["warnings"]:
        print(f"WARNING: {w}")
    if not result["ok"]:
        print(f"The retrieval data in {args.root} is not usable:", file=sys.stderr)
        for problem in result["problems"]:
            print(f"  - {problem}", file=sys.stderr)
        print("See docs/DOCKER_SETUP.md, section 'The retrieval data'.", file=sys.stderr)
        return 1
    print(f"OK: retrieval data in {args.root} ({'checksums verified' if args.full else 'structure and sizes'}): "
          + ", ".join(f"{k} {v}" for k, v in result["builds"].items())
          + f"; models: {', '.join(result['models'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
