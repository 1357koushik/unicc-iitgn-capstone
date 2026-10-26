"""
threat_retrieval_engine/indicators.py
=====================================
Single canonical source of truth for regex patterns, common threat actors,
malware families, and MITRE ATT&CK technique mappings across all engine modules.
Eliminates duplication across feature_extractor, confidence, helpers, and tests (R44).
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

# High-profile threat actors (lowercase normalized for matching)
COMMON_ACTORS: list[str] = [
    "apt29", "apt28", "cozy bear", "fancy bear", "lazarus", "fin7", "sandworm",
    "volt typhoon", "wannacry", "carbanak", "lockbit", "blackcat"
]

# Common malware families
COMMON_MALWARE: list[str] = [
    "psexec", "mimikatz", "cobalt strike", "eternalblue", "trickbot", "emotet",
    "qakbot", "bloodhound", "empire", "covenant"
]

# Tool / Malware to MITRE technique mappings
TOOL_TO_TECH: dict[str, list[str]] = {
    "psexec": ["T1021.002", "T1569.002"],
    "mimikatz": ["T1003.001"],
    "cobalt strike": ["T1071.001", "T1059"],
    "eternalblue": ["T1210"],
}
