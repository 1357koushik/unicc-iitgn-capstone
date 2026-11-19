"""
Unit test suite verifying all LLM Subsystem components, schemas, gateways, and metrics.
"""

import os

import pytest
from llm.schemas.cyber_entities import ExtractedCyberEntities, IndicatorOfCompromise, VulnerabilityReference
from llm.schemas.investigation import InvestigationResult, EvidenceCitation, PatchDetails
from llm.schemas.report_summary import ThreatReportSummary
from llm.gateway.factory import get_llm_provider, MockLLMProvider
from llm.gateway.api.gemini_provider import GeminiProvider
from llm.gateway.interface import LLMGatewayError, LLMValidationError
from llm.evaluation.metrics import (
    calculate_prf1,
    calculate_groundedness_score,
    calculate_patch_metrics,
    calculate_extraction_metrics,
)
from llm.workflows.extractor import CyberEntityExtractor
from llm.workflows.summarizer import ReportSummarizer


def test_cyber_entities_coercion_and_any_type():
    """Verifies that Any is defined and string lists of CVEs/IOCs are properly coerced."""
    assert "v" in ExtractedCyberEntities.sanitize_vulnerabilities.__annotations__

    raw = {
        "vulnerabilities": ["CVE-2024-21410", "CVE-2023-4966"],
        "iocs": ["198.51.100.24", "malicious-domain.com", "a" * 64],
        "threat_actors": ["APT28"],
        "malware_families": ["Cobalt Strike"],
    }
    entities = ExtractedCyberEntities.model_validate(raw)
    assert len(entities.vulnerabilities) == 2
    assert entities.vulnerabilities[0].cve_id == "CVE-2024-21410"
    assert entities.vulnerabilities[1].cve_id == "CVE-2023-4966"
    assert len(entities.iocs) == 3
    assert entities.iocs[0].type == "ipv4"
    assert entities.iocs[0].value == "198.51.100.24"
    assert entities.iocs[1].type == "domain"
    assert entities.iocs[2].type == "sha256"


def test_investigation_result_mitre_tactics():
    """Verifies that mitre_tactics and associated_mitre_tactics are present and populated."""
    res = InvestigationResult.model_validate({
        "query_observation": "Test observation",
        "match_status": "Strong",
        "assessment_narrative": "Grounded narrative",
        "mitre_tactics": ["Initial Access", "Lateral Movement"],
    })
    d = res.to_dict()
    assert "mitre_tactics" in d
    assert "associated_mitre_tactics" in d
    assert "Lateral Movement" in d["associated_mitre_tactics"]


def test_report_summary_string_coercion():
    """Verifies that comma-separated strings are coerced into lists for summary fields."""
    summary = ThreatReportSummary.model_validate({
        "title": "Advisory",
        "executive_summary": "Details",
        "affected_products": "Windows Server 2019, Apache HTTP Server",
        "key_tactics": "Phishing, Credential Theft",
    })
    assert len(summary.affected_products) == 2
    assert summary.affected_products[0] == "Windows Server 2019"
    assert summary.affected_products[1] == "Apache HTTP Server"
    assert len(summary.key_tactics) == 2


def test_mock_llm_provider():
    """Verifies that the mock provider works out-of-the-box via get_llm_provider."""
    provider = get_llm_provider(backend="mock")
    assert isinstance(provider, MockLLMProvider)

    summary = provider.generate_structured("Summarize report", schema_cls=ThreatReportSummary)
    assert isinstance(summary, ThreatReportSummary)
    assert summary.threat_level == "High"

    entities = provider.generate_structured("Extract entities", schema_cls=ExtractedCyberEntities)
    assert isinstance(entities, ExtractedCyberEntities)
    assert len(entities.vulnerabilities) > 0

    inv = provider.generate_structured("Investigate threat observation", schema_cls=InvestigationResult)
    assert isinstance(inv, InvestigationResult)
    assert inv.match_status == "Strong"


def test_gemini_provider_url_and_fallback():
    """Verifies that GeminiProvider doesn't produce 'models/None:generateContent'."""
    from llm.gateway.api.gemini_provider import DEFAULT_GEMINI_MODEL
    p = GeminiProvider(model_name=None, api_key="fake-test-key")
    assert p.model_name == (os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL)
    assert f"models/{p.model_name}:generateContent" in p.url


def test_groundedness_metrics_edge_cases():
    """Verifies empty citation loophole fix and unsupported scenario zero-citation handling."""
    # Unsupported scenario: 0 provided evidence chunks, 0 citations -> should be 1.0 (0 hallucinations)
    unsupported_eval = calculate_groundedness_score(citations=[], provided_evidence_ids=[])
    assert unsupported_eval["groundedness_score"] == 1.0
    assert unsupported_eval["hallucinated_citations"] == 0

    # Provided evidence exists, but model returns empty citation -> should NOT match
    empty_cit_eval = calculate_groundedness_score(
        citations=[{"document_id": ""}, {"document_id": "a"}],
        provided_evidence_ids=["CVE-2017-0144_NVD"]
    )
    assert empty_cit_eval["groundedness_score"] == 0.0
    assert empty_cit_eval["verified_citations"] == 0


def test_prf1_single_character_prevention():
    """Verifies that relaxed matching does not award credit for single-char hallucinations."""
    res = calculate_prf1(predicted={"a"}, ground_truth={"lazarus group"}, relaxed=True)
    assert res["tp"] == 0
    assert res["precision"] == 0.0


def test_patch_metrics_includes_workarounds():
    """Verifies that workaround metrics are factored into composite precision."""
    patch_eval = calculate_patch_metrics(
        extracted_patch={
            "patch_status": "Available",
            "affected_versions": ["v1.0"],
            "fixed_versions": ["v1.1"],
            "remediation_workarounds": ["Disable SMB"],
        },
        ground_truth_patch={
            "patch_status": "Available",
            "affected_versions": ["v1.0"],
            "fixed_versions": ["v1.1"],
            "remediation_workarounds": ["Disable SMB"],
        }
    )
    assert patch_eval["composite_precision"] == 1.0


def test_empty_evidence_returns_honest_unsupported():
    """Verify that when zero evidence chunks exist, investigator returns Unsupported without hallucinating."""
    from llm.workflows.investigator import ThreatInvestigator
    provider = MockLLMProvider()
    investigator = ThreatInvestigator(provider)
    res = investigator.investigate("Unknown observation", retrieved_evidence=[])
    assert res.match_status == "Unsupported"
    assert res.supporting_citations == []
    assert res.potential_threat_actors == []


def test_zero_padded_citation_mapping():
    """Verify that DOC-001 or doc-01 resolves to real document ID without Unverified Citation tag."""
    from llm.workflows.investigator import ThreatInvestigator
    provider = MockLLMProvider()
    investigator = ThreatInvestigator(provider)
    res = investigator.investigate(
        "Observation",
        retrieved_evidence=[{"document_id": "CVE-2017-0144_NVD", "content": "Evidence text"}]
    )
    assert len(res.supporting_citations) > 0
    assert all("[Unverified Citation" not in c.key_excerpt for c in res.supporting_citations)
    assert res.supporting_citations[0].document_id == "CVE-2017-0144_NVD"


def test_unwrap_container_keys():
    """Verify that if LLM wraps output in 'threat_summary' or 'result', it is unwrapped seamlessly."""
    import json
    from llm.schemas.investigation import InvestigationResult
    from llm.gateway.interface import LLMProvider

    class WrapperProvider(LLMProvider):
        def generate(self, prompt, **kwargs):
            return json.dumps({
                "threat_summary": {
                    "query_observation": "Test obs",
                    "match_status": "Strong",
                    "assessment_narrative": "Narrative",
                    "potential_threat_actors": ["APT28"],
                    "associated_malware": ["Cobalt Strike"],
                    "associated_cves": ["CVE-2017-0144"],
                    "patch_details": {"patch_status": "Available"},
                    "confidence_level": "High",
                    "supporting_citations": []
                }
            })

    p = WrapperProvider("mock")
    res = p.generate_structured("prompt", InvestigationResult)
    assert res.match_status == "Strong"
    assert res.potential_threat_actors == ["APT28"]


def test_evidence_citation_observed_overlap_string_coercion():
    """Verify that string observed_overlap from LLMs (e.g. 'Exact') coerces to list of strings."""
    from llm.schemas.investigation import EvidenceCitation, InvestigationResult

    c = EvidenceCitation.model_validate({
        "document_id": "DOC-1",
        "key_excerpt": "Quote",
        "observed_overlap": "Exact"
    })
    assert c.observed_overlap == ["Exact"]

    res = InvestigationResult.model_validate({
        "query_observation": "Obs",
        "match_status": "Exact",
        "assessment_narrative": "Narrative",
        "supporting_citations": [{
            "document_id": "DOC-1",
            "key_excerpt": "Quote",
            "observed_overlap": "Weak"
        }]
    })
    assert res.supporting_citations[0].observed_overlap == ["Weak"]
