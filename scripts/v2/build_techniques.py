"""Build the technique knowledge base for the technique route (threat_retrieval_engine/v2/techniques.py).

    python scripts/v2/build_techniques.py --out ~/team2/techniques/builds --encoders bge-large securebert2 \
        [--attack <C9 build dir>] [--threads 8]

Writes <out>/<build_id>/entries.jsonl, emb_<encoder>.npy, manifest.json and updates <out>/LATEST. An encoder can be
added to an existing build with --build <build_id> (entries are reused, the C9 build must match).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from threat_retrieval_engine.v2.system import _attack_store                     # noqa: E402
from threat_retrieval_engine.v2.techniques import ENCODERS, Encoder, kb_entries, models_dir  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--encoders", nargs="*", default=[], choices=sorted(ENCODERS))
    ap.add_argument("--attack")
    ap.add_argument("--build")
    ap.add_argument("--threads", type=int)
    a = ap.parse_args()
    out = a.out.expanduser()
    atk = _attack_store(a.attack)
    entries = kb_entries(atk)
    lines = [json.dumps({"doc_id": e.doc_id, "kind": e.kind, "text": e.text}) for e in entries]
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    if a.build:
        bdir = out / a.build
        man = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
        if man["entries_sha256"] != digest:
            print("entries differ from the existing build", file=sys.stderr)
            return 1
    else:
        bid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + digest[:10]
        bdir = out / bid
        bdir.mkdir(parents=True)
        (bdir / "entries.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        man = {"build_id": bid, "attack_build": atk.build_id, "attack_version": atk.attack_version,
               "entries": len(entries), "techniques": len({e.doc_id for e in entries}),
               "procedure_entries": sum(e.kind == "procedure" for e in entries), "entries_sha256": digest,
               }
    for name in a.encoders:
        t0 = time.time()
        enc = Encoder(name, threads=a.threads)
        m = enc.docs([e.text for e in entries])
        np.save(bdir / f"emb_{name}.npy", m)
        rev = Path(enc.path) / "REVISION"
        info = {"path": enc.path, "revision": rev.read_text().strip() if rev.exists() else None,
                "dim": int(m.shape[1]), "seconds": round(time.time() - t0, 1)}
        (bdir / f"encoder_{name}.json").write_text(json.dumps(info, indent=1), encoding="utf-8")
        print(name, m.shape, f"{time.time() - t0:.0f}s", flush=True)
    if not a.build:                       # encoders run in parallel each write encoder_<name>.json only
        (bdir / "manifest.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
        (out / "LATEST").write_text(bdir.name, encoding="utf-8")
    print("build", bdir, "models", models_dir())
    return 0


if __name__ == "__main__":
    sys.exit(main())
