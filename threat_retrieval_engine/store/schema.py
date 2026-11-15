"""SQLite schema of the C1 document store (one row per CVE)."""
from __future__ import annotations

STORE_VERSION = "c1-1.0.0"

# Columns stored as JSON text.
JSON_COLUMNS = ("cvss", "cwe_ids", "weaknesses", "cpe", "affected", "kev", "epss", "references", "tags", "dates",
                "assigner", "provenance")

CVE_COLUMNS = (
    "cve_id", "state", "searchable", "description_kind", "title", "description", "description_source",
    "vendor_product", "weakness", "aliases", "kev_text", "dense_text", "published", "modified", "nvd_status",
    "sources", "kev_listed", "epss_score", "epss_percentile",
    "cvss", "cwe_ids", "weaknesses", "cpe", "affected", "kev", "epss", "references", "tags", "dates", "assigner",
    "provenance", "content_hash", "similar_group", "store_version",
)

DDL = """
CREATE TABLE cve (
    cve_id             TEXT PRIMARY KEY,
    state              TEXT NOT NULL CHECK (state IN ('published', 'rejected', 'reserved')),
    searchable         INTEGER NOT NULL CHECK (searchable IN (0, 1)),
    description_kind   TEXT NOT NULL,          -- ok | empty | placeholder | reserved | rejected
    title              TEXT,                   -- CNA title
    description        TEXT,                   -- best English description (source in description_source)
    description_source TEXT,                   -- cve_list_cna | nvd | kev | cve_list_cna_rejected_reason
    vendor_product     TEXT,                   -- up to 10 humanised "Vendor Product" labels, "; "-separated
    weakness           TEXT,                   -- "CWE-79 <name>; ..." plus CNA free-text problem types
    aliases            TEXT,                   -- nickname and advisory-ID aliases, "; "-separated
    kev_text           TEXT,                   -- KEV vulnerability name + short description
    dense_text         TEXT,                   -- title. vendor product. description. weakness. (searchable rows)
    published          TEXT,                   -- YYYY-MM-DD (CVE List datePublished, else NVD published)
    modified           TEXT,                   -- latest source update timestamp
    nvd_status         TEXT,
    sources            TEXT NOT NULL,          -- comma list of nvd, cve_list, kev, epss
    kev_listed         INTEGER NOT NULL CHECK (kev_listed IN (0, 1)),
    epss_score         REAL,
    epss_percentile    REAL,
    cvss               TEXT NOT NULL,          -- JSON: [{version, vector, score, severity, sources:[...]}]
    cwe_ids            TEXT NOT NULL,          -- JSON: ["CWE-79", ...]
    weaknesses         TEXT NOT NULL,          -- JSON: [{id, name, name_source, sources}]
    cpe                TEXT NOT NULL,          -- JSON: NVD CPE matches with configuration structure and role
    affected           TEXT NOT NULL,          -- JSON: CNA / ADP / NVD affected products with versions
    kev                TEXT,                   -- JSON: KEV fields when listed, else NULL
    epss               TEXT,                   -- JSON: {score, percentile, date, score_date, model_version}
    "references"       TEXT NOT NULL,          -- JSON: [{url, origins, tags, name}]
    tags               TEXT NOT NULL,          -- JSON: NVD cveTags and CNA tags (e.g. disputed)
    dates              TEXT NOT NULL,          -- JSON: per-source dates
    assigner           TEXT NOT NULL,          -- JSON: {org_id, short_name, nvd_source_identifier}
    provenance         TEXT NOT NULL,          -- JSON: {sources: {...}, fields: {...}, conflicts: {...}}
    content_hash       TEXT NOT NULL,          -- sha256 of the searchable fields (incremental re-embedding)
    similar_group      TEXT,                   -- canonical CVE ID of a near-identical-description group
    store_version      TEXT NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_cve_searchable ON cve(searchable, cve_id);
CREATE INDEX idx_cve_similar_group ON cve(similar_group) WHERE similar_group IS NOT NULL;
CREATE INDEX idx_cve_published ON cve(published);

CREATE TABLE aliases (
    cve_id           TEXT NOT NULL REFERENCES cve(cve_id),
    alias            TEXT NOT NULL,
    alias_norm       TEXT NOT NULL,            -- lower-case alphanumerics ("Dirty COW" -> "dirtycow")
    kind             TEXT NOT NULL CHECK (kind IN ('nickname', 'advisory_id', 'title')),
    source           TEXT NOT NULL,            -- exploitdb | metasploit_modules | nuclei_templates | kev | cve_list | cve_description
    source_record_id TEXT NOT NULL,
    position         TEXT NOT NULL,            -- quoted | paren | camel | known_as | bulletin | title
    record_cves      INTEGER NOT NULL,         -- number of CVEs the source record names
    PRIMARY KEY (cve_id, alias_norm, kind, source, source_record_id)
) WITHOUT ROWID;

CREATE INDEX idx_aliases_norm ON aliases(alias_norm);

CREATE TABLE rejected_records (
    source    TEXT NOT NULL,
    record_id TEXT NOT NULL,
    reason    TEXT NOT NULL,
    detail    TEXT,
    PRIMARY KEY (source, record_id)
) WITHOUT ROWID;

CREATE TABLE changes (                         -- against --previous build, when given
    cve_id TEXT PRIMARY KEY,
    change TEXT NOT NULL CHECK (change IN ('added', 'changed', 'removed'))
) WITHOUT ROWID;

CREATE TABLE v1_comparison (                   -- with --v1-corpus: why each CVE is missing from the v1 corpus
    cve_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    detail TEXT
) WITHOUT ROWID;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"""
