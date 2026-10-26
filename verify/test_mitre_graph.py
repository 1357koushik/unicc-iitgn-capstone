from __future__ import annotations

import json
import tempfile
from pathlib import Path
import pytest
from threat_retrieval_engine.search_engine.mitre_graph import (
    MitreAttackGraph,
    build_graph_from_bundle,
    AttackNode,
)


def test_mitre_graph_load_and_query():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--1",
                "name": "APT29",
                "aliases": ["Cozy Bear"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Remote Services",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1021.002"}],
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "WellMess",
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0514"}],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--1",
                "relationship_type": "uses",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "source_ref": "intrusion-set--1",
                "target_ref": "malware--1",
                "relationship_type": "uses",
            },
        ],
    }

    graph = build_graph_from_bundle(bundle)
    assert len(graph.nodes) >= 3

    # Query actor by alias or name
    stix_id = graph.resolve("Cozy Bear")
    assert stix_id == "intrusion-set--1"

    node = graph.node("Cozy Bear")
    assert node is not None
    assert node.name == "APT29"

    # Query techniques for actor
    techs = graph.techniques_for_actor("APT29")
    assert "T1021.002" in techs

    # Query malware for actor
    malware = graph.malware_for_actor("APT29")
    assert "WellMess" in malware

    # Expand graph
    expanded = graph.expand(threat_actors=["APT29"])
    assert len(expanded) >= 2
