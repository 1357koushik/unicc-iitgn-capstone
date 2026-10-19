"""
Downloads the public NSL-KDD dataset (its official training file and test file).

NSL-KDD is a standard labelled benchmark for network intrusion detection, published by
the Canadian Institute for Cybersecurity, University of New Brunswick:
    https://www.unb.ca/cic/datasets/nsl.html
The official page asks visitors to fill in a form, so this script uses a widely used
public copy on GitHub. Every file is checked against a fixed SHA-256 fingerprint, so
everyone on the team trains and tests on exactly the same data, and a changed or
damaged copy is refused instead of being used silently.

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.download_data
"""
import hashlib
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Tuple

from network_sensor.paths import dataset_dir

MIRROR_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"

# file name -> (name in the GitHub copy, SHA-256 fingerprint, number of records)
# The record counts match the counts published for the official NSL-KDD files.
FILES: Dict[str, Tuple[str, str, int]] = {
    "KDDTrain+.txt": ("KDDTrain%2B.txt",
                      "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95", 125_973),
    "KDDTest+.txt": ("KDDTest%2B.txt",
                     "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84", 22_544),
}


class DownloadError(Exception):
    """The file could not be downloaded, or it was not the file we expected."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_file(name: str, target_dir: Path, base_url: str = MIRROR_URL,
                  files: Dict[str, Tuple[str, str, int]] = FILES, timeout: int = 60) -> Path:
    """Download one file into target_dir and check its fingerprint.

    If the right file is already there it is kept. The download goes to a temporary
    '.part' file first and only becomes the real file after the fingerprint matches,
    so a failed or wrong download never leaves a half-finished file behind."""
    remote_name, expected_sha256, _ = files[name]
    target = Path(target_dir) / name
    if target.exists() and sha256_of(target) == expected_sha256:
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    try:
        try:
            with urllib.request.urlopen(base_url + remote_name, timeout=timeout) as response, \
                    open(partial, "wb") as out:
                shutil.copyfileobj(response, out)
        except (urllib.error.URLError, OSError) as e:
            raise DownloadError(f"Could not download {name}: {e}") from e

        actual_sha256 = sha256_of(partial)
        if actual_sha256 != expected_sha256:
            raise DownloadError(
                f"{name} does not match the expected fingerprint, so it was NOT saved.\n"
                f"  expected {expected_sha256}\n  received {actual_sha256}")
        partial.replace(target)
    finally:
        if partial.exists():
            partial.unlink()
    return target


def main() -> int:
    folder = dataset_dir()
    print(f"Saving the NSL-KDD dataset to: {folder}")
    for name, (_, _, records) in FILES.items():
        try:
            download_file(name, folder)
        except DownloadError as e:
            print(f"\nERROR: {e}")
            print("\nIf downloads are blocked on this network, download the two files in a "
                  f"browser from\n  {MIRROR_URL}\nand put them in the folder above, then run this "
                  "command again to check them.")
            return 1
        print(f"  OK  {name:<14} {records:>7,} records, fingerprint verified")
    print("\nDone. Next step:  python -m network_sensor.train")
    return 0


if __name__ == "__main__":
    sys.exit(main())
