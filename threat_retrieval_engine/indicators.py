"""
threat_retrieval_engine/indicators.py
=====================================
Single canonical source of the identifier regex patterns shared by the engine modules (R44).

Threat actor, malware and tool names are not listed here: they come from the C9 ATT&CK build through its
gazetteer (`threat_retrieval_engine.attack.runtime.entity_names`), and technique links of software come
from its graph (`AttackGraph.techniques_used_by`).
"""

from __future__ import annotations

import re

# Standard regex patterns
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
