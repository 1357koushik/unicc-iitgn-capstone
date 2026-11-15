"""C9 ATT&CK store: ATT&CK Enterprise groups, software, techniques, mitigations and campaigns as documents,
their STIX relationships as a graph, CVE links with evidence, and the entity-name gazetteer for the parser.

Build:  python -m threat_retrieval_engine.attack.build --sources <data/sources> --store <C1 build> --out <data/attack>
Check:  python -m threat_retrieval_engine.attack.check_c9 [--attack DIR] [--store DIR] [--benchmark DIR]
Read:   from threat_retrieval_engine.attack import AttackStore

Plan reference: docs/RETRIEVAL_V2_PLAN.md section 4.4 (ATT&CK content) and 4.5 (entity route). Replaces the
v1 hardcoded ATT&CK stub graph and the hardcoded actor, malware and tool lists.
"""
from .gazetteer import Candidate, Gazetteer, Mention
from .graph import AttackGraph, format_edge
from .reader import AttackStore, resolve_attack_build, to_doc_id
from .schema import ATTACK_STORE_VERSION

__all__ = ["AttackStore", "AttackGraph", "Gazetteer", "Mention", "Candidate", "resolve_attack_build", "to_doc_id",
           "format_edge", "ATTACK_STORE_VERSION"]
