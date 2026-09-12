"""
test_mitre_graph.py
===================
Tests for mitre_graph.py — the in-process MITRE ATT&CK STIX graph.

A tiny synthetic STIX bundle stands in for the full enterprise-attack.json,
so no download is needed.

Run with: pytest verify/test_mitre_graph.py -v
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from mitre_graph import build_graph_from_bundle, load_attack_bundle


def _bundle() -> dict:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt29",
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0016"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1021-002",
                "name": "SMB/Windows Admin Shares",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1021.002"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--miniduke",
                "name": "MiniDuke",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0051"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deprecated",
                "name": "Deprecated Technique",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt29",
                "target_ref": "attack-pattern--t1021-002",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt29",
                "target_ref": "malware--miniduke",
            },
        ],
    }


@pytest.fixture
def graph():
    return build_graph_from_bundle(_bundle())


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_resolve_by_attack_id(graph):
    node = graph.node("T1021.002")
    assert node is not None
    assert node.name == "SMB/Windows Admin Shares"


def test_resolve_by_alias(graph):
    node = graph.node("Cozy Bear")
    assert node is not None
    assert node.attack_id == "G0016"


def test_deprecated_nodes_skipped(graph):
    assert graph.node("T9999") is None


# ---------------------------------------------------------------------------
# Traversal queries
# ---------------------------------------------------------------------------


def test_techniques_for_actor(graph):
    assert graph.techniques_for_actor("APT29") == ["T1021.002"]


def test_malware_for_actor(graph):
    assert "MiniDuke" in graph.malware_for_actor("APT29")


def test_actors_for_technique_reverse(graph):
    assert graph.actors_for_technique("T1021.002") == ["APT29"]


def test_relationship_paths_are_readable(graph):
    paths = graph.relationship_paths("APT29")
    assert "G0016 -[uses]-> T1021.002" in paths


# ---------------------------------------------------------------------------
# expand()
# ---------------------------------------------------------------------------


def test_expand_from_actor(graph):
    out = graph.expand(threat_actors=["APT29"])
    assert "T1021.002" in out["techniques"]
    assert "MiniDuke" in out["malware"]
    assert any("uses" in r for r in out["relationships"])


def test_expand_from_technique(graph):
    out = graph.expand(techniques=["T1021.002"])
    assert "APT29" in out["actors"]


def test_expand_unknown_entity_is_safe(graph):
    out = graph.expand(threat_actors=["NonexistentGroup"])
    assert out["actors"] == []


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def test_load_attack_bundle_from_file(tmp_path):
    p = tmp_path / "enterprise-attack.json"
    p.write_text(json.dumps(_bundle()), encoding="utf-8")
    g = load_attack_bundle(p)
    assert g.techniques_for_actor("APT29") == ["T1021.002"]


def test_load_missing_bundle_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_attack_bundle(tmp_path / "nope.json")
