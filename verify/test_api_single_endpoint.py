"""
test_api_single_endpoint.py
===========================
Verifies the single unified POST REST API endpoint.
Tests with the exact Team 3 sample query and verifies response structure.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure root directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_post_match_team3_format(client):
    payload = {
        "query": "Observed lateral movement using PsExec following exploitation of CVE-2017-0144 from 198.51.100.24 using technique T1021.002",
        "top_k": 5,
        "alpha": 0.5,
    }

    response = client.post("/match", json=payload)
    assert response.status_code == 200

    data = response.json()

    # 1. Top-level keys
    assert "query_threat_id" in data
    assert data["query_threat_id"].startswith("query_")
    assert "top_matches" in data
    assert "pipeline_profile" in data

    # 2. Pipeline profile timings
    prof = data["pipeline_profile"]
    assert "exact_match_ms" in prof
    assert "vector_database_ms" in prof
    assert "knowledge_graph_ms" in prof
    assert "scoring_ms" in prof
    assert "citation_ms" in prof
    assert "total_ms" in prof
    assert isinstance(prof["exact_match_ms"], (int, float))
    assert isinstance(prof["vector_database_ms"], (int, float))
    assert isinstance(prof["knowledge_graph_ms"], (int, float))

    # 3. Matches
    matches = data["top_matches"]
    assert len(matches) > 0
    top = matches[0]

    assert top["rank"] == 1
    assert "chunk_id" in top
    assert isinstance(top["composite_score"], float)
    assert top["confidence_tier"] in {"EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"}

    # 4. Evidence breakdown
    eb = top["evidence_breakdown"]
    assert "ioc_similarity" in eb
    assert "cve_similarity" in eb
    assert "ttp_similarity" in eb
    assert "semantic_similarity" in eb

    # 5. Attribution
    attr = top["attribution"]
    assert "matching_iocs" in attr
    assert "matching_cves" in attr
    assert "shared_malware" in attr
    assert "matching_mitre_techniques" in attr
    assert "198.51.100.24" in attr["matching_iocs"]
    assert "CVE-2017-0144" in attr["matching_cves"]
    assert "T1021.002" in attr["matching_mitre_techniques"]
    assert "PsExec" in attr["shared_malware"]

    # 6. STIX Relationships from Knowledge Graph
    assert "stix_relationships" in top
    assert isinstance(top["stix_relationships"], list)
    assert any("T1021.002" in rel for rel in top["stix_relationships"])

    # 7. Citations
    assert "citations" in top
    assert len(top["citations"]) > 0
    cit = top["citations"][0]
    assert "doc_id" in cit
    assert "doc_title" in cit
    assert "source_org" in cit
    assert "published_date" in cit
    assert "page_number" in cit
    assert "text_snippet" in cit


def test_post_api_v1_threats_match_alias(client):
    payload = {
        "query": "Exploitation of CVE-2017-0144",
        "top_k": 3,
        "alpha": 0.5,
    }
    response = client.post("/api/v1/threats/match", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "query_threat_id" in data
    assert len(data["top_matches"]) > 0
