"""Layout of a C3 dense index build (``data/dense/<build_id>/``).

Files
-----
``vectors.npy``      float32, C order, shape (documents, dim); row i is document i's L2-normalised vector.
``doc_ids.txt``      one doc_id per line (UTF-8, ``\\n``), row order of ``vectors.npy``.
``manifest.json``    build ID, format, model (name, repository, revision, weights sha256, pooling, prefixes,
                     token caps) or the v1 export description, inputs (C1 store and C9 ATT&CK build IDs, the
                     documents' sha256), ``kind_ranges`` (row range of every document kind), counts, the
                     sha256 of both files above, the code fingerprint and the environment.
``documents.jsonl``  (encoded builds) the exact texts that were embedded, with their content hashes; kept so a
                     build can be checked and re-encoded without the store.

Row order: kinds in ``KINDS`` order, doc_ids increasing (text order) inside a kind. A row's position is the
deterministic tie-break of the search, so equal scores are ordered by document ID within a kind and CVE
documents before ATT&CK documents.

Pointers in the output root: ``LATEST`` (newest successful build), ``PREVIOUS`` (the one before). A build never
deletes another; ``--prune`` keeps LATEST, PREVIOUS, CURRENT and every build named by a dependant manifest.
"""
from __future__ import annotations

DENSE_FORMAT = "c3-dense-1"
KINDS = ("cve", "attack")
VECTORS_FILE = "vectors.npy"
DOC_IDS_FILE = "doc_ids.txt"
DOCUMENTS_FILE = "documents.jsonl"
MANIFEST_FILE = "manifest.json"
NORM_TOLERANCE = 1e-3          # |norm - 1| allowed for a stored vector (float32 rounding of unit vectors)
