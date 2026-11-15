"""SQLite schema of the C9 ATT&CK build (documents, graph, CVE links, gazetteer)."""
from __future__ import annotations

ATTACK_STORE_VERSION = "c9-1.0.0"

DOC_KINDS = ("group", "software", "technique", "mitigation", "campaign")

# Columns stored as JSON text.
JSON_COLUMNS = ("aliases_list", "tactics_list", "platforms_list", "attrs")

OBJECT_COLUMNS = (
    "doc_id", "attack_id", "stix_id", "stix_type", "doc_kind", "software_type", "is_subtechnique", "parent_doc_id",
    "name", "title", "aliases", "description", "dense_text", "tactics", "platforms", "url", "version", "created",
    "modified", "first_seen", "last_seen", "state", "searchable", "revoked_by", "aliases_list", "tactics_list",
    "platforms_list", "attrs", "content_hash", "store_version",
)

# Text fields an index reads, with the same names and meaning as in the C1 CVE store where one exists
# (`title`, `aliases`, `description`, `dense_text`). `tactics` and `platforms` exist only here.
TEXT_FIELDS = ("title", "aliases", "description", "tactics", "platforms")

DDL = """
CREATE TABLE objects (
    doc_id          TEXT PRIMARY KEY,          -- attack:<ATT&CK ID>
    attack_id       TEXT NOT NULL UNIQUE,      -- G0016, S0154, T1059.001, M1050, C0022
    stix_id         TEXT NOT NULL UNIQUE,
    stix_type       TEXT NOT NULL,             -- intrusion-set | malware | tool | attack-pattern | course-of-action | campaign
    doc_kind        TEXT NOT NULL CHECK (doc_kind IN ('group', 'software', 'technique', 'mitigation', 'campaign')),
    software_type   TEXT,                      -- malware | tool (software only)
    is_subtechnique INTEGER NOT NULL CHECK (is_subtechnique IN (0, 1)),
    parent_doc_id   TEXT,                      -- parent technique of a sub-technique (subtechnique-of edge)
    name            TEXT NOT NULL,             -- ATT&CK name
    title           TEXT NOT NULL,             -- name; "Parent: Sub" for a sub-technique
    aliases         TEXT,                      -- aliases other than the name, "; "-separated
    description     TEXT,                      -- markdown links reduced to their text, citations and HTML removed
    dense_text      TEXT,                      -- title. aliases. tactics. description, IDs removed (searchable rows)
    tactics         TEXT,                      -- tactic names, "; "-separated (techniques)
    platforms       TEXT,                      -- "; "-separated
    url             TEXT,
    version         TEXT,                      -- x_mitre_version
    created         TEXT,
    modified        TEXT,
    first_seen      TEXT,                      -- campaigns
    last_seen       TEXT,                      -- campaigns
    state           TEXT NOT NULL CHECK (state IN ('active', 'revoked', 'deprecated')),
    searchable      INTEGER NOT NULL CHECK (searchable IN (0, 1)),
    revoked_by      TEXT,                      -- revoked objects: doc_id of the final active replacement
    aliases_list    TEXT NOT NULL,             -- JSON: aliases other than the name
    tactics_list    TEXT NOT NULL,             -- JSON: [{shortname, name, attack_id}]
    platforms_list  TEXT NOT NULL,             -- JSON
    attrs           TEXT NOT NULL,             -- JSON: kind-specific STIX fields (domains, contributors, ...)
    content_hash    TEXT NOT NULL,             -- sha256 of the searchable text fields
    store_version   TEXT NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_objects_searchable ON objects(searchable, doc_id);
CREATE INDEX idx_objects_kind ON objects(doc_kind, searchable);

CREATE TABLE edges (
    rel_stix_id     TEXT PRIMARY KEY,          -- STIX relationship ID
    rel_type        TEXT NOT NULL,             -- uses | mitigates | subtechnique-of | attributed-to | revoked-by | ...
    src_doc_id      TEXT NOT NULL REFERENCES objects(doc_id),
    dst_doc_id      TEXT NOT NULL REFERENCES objects(doc_id),
    src_attack_id   TEXT NOT NULL,
    dst_attack_id   TEXT NOT NULL,
    description     TEXT,                      -- cleaned like object descriptions
    orig_src_doc_id TEXT NOT NULL,             -- endpoints as written in STIX (differ when redirected)
    orig_dst_doc_id TEXT NOT NULL,
    redirected      TEXT,                      -- NULL | src | dst | both: endpoint moved from a revoked object
    created         TEXT,
    modified        TEXT
) WITHOUT ROWID;

CREATE INDEX idx_edges_src ON edges(src_doc_id, rel_type);
CREATE INDEX idx_edges_dst ON edges(dst_doc_id, rel_type);

CREATE TABLE cve_links (
    doc_id        TEXT NOT NULL REFERENCES objects(doc_id),
    cve_id        TEXT NOT NULL,               -- exists and is searchable in the C1 store build named in meta
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('object_description', 'object_external_reference',
                     'relationship_description', 'relationship_external_reference', 'kev_mapping')),
    evidence_ref  TEXT NOT NULL,               -- STIX ID (+ field) or KEV mapping key
    role          TEXT NOT NULL,               -- self | relationship_source | relationship_target | mapped_technique
    detail        TEXT NOT NULL,               -- JSON: text snippet / mapping fields / redirect
    PRIMARY KEY (doc_id, cve_id, evidence_kind, evidence_ref, role)
) WITHOUT ROWID;

CREATE INDEX idx_cve_links_cve ON cve_links(cve_id);

CREATE TABLE gazetteer (
    key          TEXT NOT NULL,                -- normalised name (C1 alias_norm: lower-case alphanumerics)
    doc_id       TEXT NOT NULL REFERENCES objects(doc_id),
    doc_kind     TEXT NOT NULL,
    surface      TEXT NOT NULL,                -- the name or alias as ATT&CK writes it
    origin       TEXT NOT NULL CHECK (origin IN ('name', 'qualified_name', 'alias', 'revoked_name')),
    fine_tokens  INTEGER NOT NULL,             -- letter/digit runs in the surface form
    PRIMARY KEY (key, doc_id)
) WITHOUT ROWID;

CREATE TABLE gazetteer_keys (
    key          TEXT PRIMARY KEY,
    n_docs       INTEGER NOT NULL,             -- > 1: ambiguous name
    kinds        TEXT NOT NULL,                -- comma list of doc kinds the key names
    policy       TEXT NOT NULL CHECK (policy IN ('anywhere', 'restricted')),
    reason       TEXT,                         -- restricted: short | corpus_term | short+corpus_term
    df_cve       INTEGER NOT NULL              -- searchable C1 CVE descriptions naming the key (any case)
) WITHOUT ROWID;

CREATE TABLE rejected (
    source    TEXT NOT NULL,                   -- stix_object | stix_relationship | cve_link | kev_mapping
    record_id TEXT NOT NULL,
    reason    TEXT NOT NULL,
    detail    TEXT,
    PRIMARY KEY (source, record_id)
) WITHOUT ROWID;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"""
