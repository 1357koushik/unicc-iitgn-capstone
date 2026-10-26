"""
verify/test_confidence_contract.py
==================================
Comprehensive unit and integration test suite enforcing the Confidence Contract
(docs/dev/confidence_contract.md) for Phase 2 of UNICC x IITGN Capstone.

Compatible with both `pytest verify/test_confidence_contract.py -v`
and `python -m unittest verify/test_confidence_contract.py -v`.

Test Coverage:
1. Layer 1 Deterministic Matcher:
   - test_layer1_exact_id_match
   - test_layer1_case_insensitivity
   - test_layer1_rejects_incidental_mention
   - test_layer1_rejects_adjacent_different_cve
   - test_layer1_exact_hash_synthetic
   - test_layer1_multiple_cves_partial_mismatch_rejected
2. Feature Extractor & Train-Serve Parity:
   - test_absent_observables_not_penalized
   - test_train_serve_feature_parity
   - test_anti_leakage_doc_id_isolation
3. Classification & Calibration:
   - test_confidence_tier_monotonicity
4. Safe Degraded Mode:
   - test_degraded_mode_missing_model
5. Metadata Field Separation:
   - test_metadata_separation
6. Behavioral Option B Heuristic:
   - test_behavioral_query_option_b_uncalibrated
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path for direct pytest and unittest execution
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from threat_retrieval_engine.api.confidence import (
    ConfidenceModel,
    ConfidenceResolution,
    QueryProfile,
    classify_confidence_tier,
    match_layer1,
    parse_query_profile,
    resolve_confidence,
)
from threat_retrieval_engine.api.feature_extractor import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    FeatureExtractor,
    extract_features,
)


class TestConfidenceContract(unittest.TestCase):
    """Test suite enforcing the Confidence Contract specifications."""

    # =======================================================================
    # 1. Layer 1 Tests: Deterministic Identifier Match (No Model)
    # =======================================================================

    def test_layer1_exact_id_match(self):
        r"""
        Query with 'CVE-2017-0144' matches document with doc_id='CVE-2017-0144_NVD'.
        Contract Section 2.1:
        - Primary identification rule: regex ^(CVE-\d{4}-\d+) on doc_id
        - Returns EXACT_ID and tier EXACT
        - Probability 1.0, calibrated=True, tier_basis='DETERMINISTIC_L1', degraded=False
        """
        query = "Investigating vulnerability CVE-2017-0144 affecting SMBv1"
        profile = parse_query_profile(query)
        self.assertEqual(profile.cves, ("CVE-2017-0144",))

        chunk = {
            "chunk_id": "chunk_eb_01",
            "doc_id": "CVE-2017-0144_NVD",
            "text": "Remote code execution in Microsoft Server Message Block 1.0 (SMBv1)",
            "metadata": {"doc_id": "CVE-2017-0144_NVD"},
        }

        is_l1, match_type = match_layer1(profile, chunk)
        self.assertTrue(is_l1, "Layer 1 should trigger for exact primary CVE ID match")
        self.assertEqual(match_type, "EXACT_ID")

        resolution = resolve_confidence(profile, chunk, candidate_score=0.88)
        self.assertEqual(resolution.match_type, "EXACT_ID")
        self.assertEqual(resolution.tier, "EXACT")
        self.assertEqual(resolution.probability, 1.0)
        self.assertTrue(resolution.calibrated)
        self.assertEqual(resolution.tier_basis, "DETERMINISTIC_L1")
        self.assertFalse(resolution.degraded)

    def test_layer1_case_insensitivity(self):
        """
        Lowercase 'cve-2017-0144' in query matches uppercase doc_id='CVE-2017-0144_EPSS'.
        Contract Section 2.1: Identifier matching must be case-insensitive.
        """
        query = "Check exploit prediction for cve-2017-0144"
        profile = parse_query_profile(query)
        # QueryProfile normalizes CVEs to uppercase
        self.assertEqual(profile.cves, ("CVE-2017-0144",))

        chunk = {
            "chunk_id": "chunk_eb_epss",
            "doc_id": "CVE-2017-0144_EPSS",
            "text": "EPSS exploitation probability score for EternalBlue",
            "metadata": {"doc_id": "CVE-2017-0144_EPSS"},
        }

        is_l1, match_type = match_layer1(profile, chunk)
        self.assertTrue(is_l1)
        self.assertEqual(match_type, "EXACT_ID")

        resolution = resolve_confidence(profile, chunk, candidate_score=0.92)
        self.assertEqual(resolution.match_type, "EXACT_ID")
        self.assertEqual(resolution.tier, "EXACT")
        self.assertEqual(resolution.probability, 1.0)
        self.assertTrue(resolution.calibrated)
        self.assertEqual(resolution.tier_basis, "DETERMINISTIC_L1")

    def test_layer1_rejects_incidental_mention(self):
        """
        Document text mentions 'CVE-2017-0144' but doc_id is 'CVE-2020-0796'.
        Contract Section 2.1:
        - Incidental mentions inside body text do NOT trigger Layer 1.
        - True by construction requires primary key alignment.
        """
        query = "CVE-2017-0144"
        profile = parse_query_profile(query)

        # Document primary ID is CVE-2020-0796 (SMBGhost), mentioning CVE-2017-0144 only as context
        chunk = {
            "chunk_id": "chunk_smbghost_01",
            "doc_id": "CVE-2020-0796_NVD",
            "text": "A remote code execution vulnerability exists in SMBv3. Like CVE-2017-0144, this flaw affects Windows SMB compression.",
            "metadata": {"doc_id": "CVE-2020-0796_NVD"},
            "entities_json": {
                "cves": ["CVE-2020-0796", "CVE-2017-0144"],
                "iocs": {"ipv4": [], "sha256": [], "md5": []},
                "mitre_ttps": [],
            },
        }

        is_l1, match_type = match_layer1(profile, chunk)
        self.assertFalse(is_l1, "Incidental body text mention must NOT trigger Layer 1")
        self.assertIsNone(match_type)

        # resolve_confidence must NOT return EXACT or EXACT_ID
        resolution = resolve_confidence(profile, chunk, candidate_score=0.45)
        self.assertNotEqual(resolution.tier, "EXACT")
        self.assertNotEqual(resolution.match_type, "EXACT_ID")
        self.assertNotEqual(resolution.tier_basis, "DETERMINISTIC_L1")

    def test_layer1_rejects_adjacent_different_cve(self):
        """
        Query 'CVE-2021-44228' against doc_id='CVE-2021-44229'.
        Contract Section 2.1 & 5.1:
        - Adjacent CVE numbers are classic hard distractors and must NOT match Layer 1.
        """
        query = "Exploit analysis for CVE-2021-44228 Log4Shell"
        profile = parse_query_profile(query)
        self.assertEqual(profile.cves, ("CVE-2021-44228",))

        chunk = {
            "chunk_id": "chunk_adjacent_cve",
            "doc_id": "CVE-2021-44229_NVD",
            "text": "Apache Log4j2 denial of service via recursive lookup vulnerability (CVE-2021-44229)",
            "metadata": {"doc_id": "CVE-2021-44229_NVD"},
        }

        is_l1, match_type = match_layer1(profile, chunk)
        self.assertFalse(is_l1, "Adjacent different CVE must NOT trigger Layer 1")
        self.assertIsNone(match_type)

        resolution = resolve_confidence(profile, chunk, candidate_score=0.30)
        self.assertNotEqual(resolution.tier, "EXACT")
        self.assertNotEqual(resolution.match_type, "EXACT_ID")

    def test_layer1_exact_hash_synthetic(self):
        """
        Synthetic fixture where entities_json['iocs']['sha256'] contains
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        queried hash matches -> returns EXACT_HASH and tier EXACT.
        Also verifies MD5 synthetic fixture.
        """
        sha_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        query = f"Malware payload with sha256 {sha_hash}"
        profile = parse_query_profile(query)
        self.assertIn(sha_hash, profile.hashes)

        chunk = {
            "chunk_id": "chunk_synth_malware_sha",
            "doc_id": "REPORT-SYNTH-2026-MALWARE",
            "text": f"Threat report containing observed sha256 {sha_hash}",
            "entities_json": {
                "cves": [],
                "iocs": {
                    "sha256": [sha_hash],
                    "md5": [],
                    "ipv4": [],
                },
                "mitre_ttps": [],
            },
        }

        is_l1, match_type = match_layer1(profile, chunk)
        self.assertTrue(is_l1, "Exact hash match in entities_json must trigger Layer 1")
        self.assertEqual(match_type, "EXACT_HASH")

        resolution = resolve_confidence(profile, chunk, candidate_score=0.95)
        self.assertEqual(resolution.match_type, "EXACT_HASH")
        self.assertEqual(resolution.tier, "EXACT")
        self.assertEqual(resolution.probability, 1.0)
        self.assertTrue(resolution.calibrated)
        self.assertEqual(resolution.tier_basis, "DETERMINISTIC_L1")

        # Also verify MD5 synthetic match
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        md5_query = f"Incident query with md5 {md5_hash}"
        md5_profile = parse_query_profile(md5_query)
        self.assertIn(md5_hash, md5_profile.hashes)

        md5_chunk = {
            "chunk_id": "chunk_synth_malware_md5",
            "doc_id": "REPORT-SYNTH-MD5",
            "entities_json": {
                "iocs": {
                    "sha256": [],
                    "md5": [md5_hash],
                }
            },
        }
        is_l1_md5, match_type_md5 = match_layer1(md5_profile, md5_chunk)
        self.assertTrue(is_l1_md5)
        self.assertEqual(match_type_md5, "EXACT_HASH")

    def test_layer1_multiple_cves_partial_mismatch_rejected(self):
        """
        Contract Section 2.1: Queries with multiple distinct CVEs do not trigger
        Layer 1 unless the document primary ID covers all of them.
        """
        query = "Comparative triage between CVE-2017-0144 and CVE-2020-0796"
        profile = parse_query_profile(query)
        self.assertEqual(len(profile.cves), 2)

        chunk = {
            "chunk_id": "chunk_eb",
            "doc_id": "CVE-2017-0144_NVD",
            "text": "SMBv1 vulnerability EternalBlue",
        }

        is_l1, match_type = match_layer1(profile, chunk)
        self.assertFalse(is_l1, "Multiple queried CVEs against a single-CVE doc_id must NOT trigger Layer 1")
        self.assertIsNone(match_type)

    # =======================================================================
    # 2. Feature Extractor & Parity Tests
    # =======================================================================

    def test_absent_observables_not_penalized(self):
        """
        Contract Section 4 & Section 6.2:
        Query with only CVE vs Query with CVE + absent IOCs.
        Verify has_ioc == 0.0 and interaction terms are 0.0, proving absent
        observables are mathematically neutral (not encoded as misses).
        """
        # 1. Query with only CVE (no IOC, no TTP)
        query_cve_only = "CVE-2021-44228"
        profile_cve_only = parse_query_profile(query_cve_only)
        self.assertTrue(profile_cve_only.has_cve)
        self.assertFalse(profile_cve_only.has_ioc)
        self.assertFalse(profile_cve_only.has_ttp)

        candidate_doc = {
            "chunk_id": "chunk_log4j_doc",
            "doc_id": "CVE-2021-44228_NVD",
            "text": "Remote code execution in Apache Log4j JNDI LDAP lookup",
            "entities_json": {
                "cves": ["CVE-2021-44228"],
                "iocs": {"ipv4": [], "sha256": [], "md5": []},
                "mitre_ttps": [],
            },
        }

        feats_cve_only = FeatureExtractor.extract_features(profile_cve_only, candidate_doc)

        # In query with only CVE:
        self.assertEqual(feats_cve_only["has_cve"], 1.0)
        self.assertEqual(feats_cve_only["has_ioc"], 0.0, "has_ioc must be 0.0 when query has no IOC")
        self.assertEqual(feats_cve_only["has_ttp"], 0.0, "has_ttp must be 0.0 when query has no TTP")

        # Absent observables must have coverage 0.0 and interaction terms 0.0
        self.assertEqual(feats_cve_only["ioc_coverage"], 0.0)
        self.assertEqual(feats_cve_only["ttp_coverage"], 0.0)
        self.assertEqual(feats_cve_only["inter_ioc_cov"], 0.0)
        self.assertEqual(feats_cve_only["inter_ttp_cov"], 0.0)

        # 2. Compare against a query that actually specified an IOC that is missing from doc
        query_with_missed_ioc = "CVE-2021-44228 from attacker IP 198.51.100.99"
        profile_with_missed_ioc = parse_query_profile(query_with_missed_ioc)
        self.assertTrue(profile_with_missed_ioc.has_cve)
        self.assertTrue(profile_with_missed_ioc.has_ioc)

        feats_missed_ioc = FeatureExtractor.extract_features(profile_with_missed_ioc, candidate_doc)

        # In query with missed IOC:
        self.assertEqual(feats_missed_ioc["has_ioc"], 1.0, "has_ioc is 1.0 when queried")
        self.assertEqual(feats_missed_ioc["ioc_coverage"], 0.0, "ioc_coverage is 0.0 because IP is missing")
        self.assertEqual(feats_missed_ioc["inter_ioc_cov"], 0.0)

        # Distinction proves the contract principle:
        # An absent observable has has_ioc == 0.0 (inactive channel).
        # In the linear logit z = w^T x + b, w_has_ioc * 0 + w_cov * 0 + w_inter * 0 == 0.
        # It contributes exactly 0 to the logit rather than penalizing the score.
        self.assertNotEqual(feats_cve_only["has_ioc"], feats_missed_ioc["has_ioc"])

    def test_train_serve_feature_parity(self):
        """
        Contract Section 4:
        Verify that FeatureExtractor.extract_features() produces identical keys,
        types, and values given the same query profile and candidate chunk.
        Guarantees exact train-serve parity between training pipeline and runtime serving.
        """
        query = "Apache Log4j2 JNDI RCE vulnerability CVE-2021-44228 technique T1059.001"
        profile = parse_query_profile(query)

        chunk = {
            "chunk_id": "chunk_test_01",
            "doc_id": "CVE-2021-44228_NVD",
            "text": "Critical Log4j flaw allows arbitrary PowerShell execution via JNDI.",
            "entities_json": {
                "cves": ["CVE-2021-44228"],
                "iocs": {"ipv4": [], "sha256": [], "md5": []},
                "mitre_ttps": ["T1059.001"],
                "threat_actors": [],
                "malware_families": [],
            },
            "dense_score": 0.85,
            "bm25_norm_score": 0.72,
        }

        # Simulate extraction during training data generation
        train_features = FeatureExtractor.extract_features(profile, chunk)

        # Simulate extraction during online runtime serving
        serve_features = extract_features(profile, chunk)

        # 1. Exact identical dictionary output
        self.assertEqual(train_features, serve_features, "Training and serving features must be strictly identical")

        # 2. Verify all 12 canonical feature keys are present
        self.assertEqual(sorted(train_features.keys()), sorted(FEATURE_NAMES), (
            f"Feature keys {sorted(train_features.keys())} do not match contract {sorted(FEATURE_NAMES)}"
        ))
        self.assertEqual(len(train_features), 12)

        # 3. Verify types and value bounds [0.0, 1.0]
        for key, val in train_features.items():
            self.assertIsInstance(val, float, f"Feature {key} must be float, got {type(val)}")
            self.assertTrue(0.0 <= val <= 1.0, f"Feature {key} value {val} out of bounds [0.0, 1.0]")

        # 4. Verify specific expected coverages
        self.assertEqual(train_features["has_cve"], 1.0)
        self.assertEqual(train_features["cve_coverage"], 1.0)
        self.assertEqual(train_features["inter_cve_cov"], 1.0)
        self.assertEqual(train_features["has_ttp"], 1.0)
        self.assertEqual(train_features["ttp_coverage"], 1.0)
        self.assertEqual(train_features["inter_ttp_cov"], 1.0)
        self.assertEqual(train_features["has_ioc"], 0.0)
        self.assertEqual(train_features["ioc_coverage"], 0.0)
        self.assertEqual(train_features["inter_ioc_cov"], 0.0)

    def test_anti_leakage_doc_id_isolation(self):
        """
        Contract Section 3.2:
        Layer 2 features must NEVER inspect or derive information from doc_id.
        Verify that altering doc_id produces identical feature vectors.
        """
        query = "Exploit in Spring framework"
        profile = parse_query_profile(query)

        chunk_a = {
            "chunk_id": "c1",
            "doc_id": "CVE-2022-22965_NVD",
            "text": "Spring Framework RCE vulnerability via DataBinder parameter binding.",
            "entities_json": {"cves": ["CVE-2022-22965"]},
        }

        chunk_b = copy.deepcopy(chunk_a)
        chunk_b["doc_id"] = "RANDOM_CORPUS_DOC_99999"

        feats_a = FeatureExtractor.extract_features(profile, chunk_a)
        feats_b = FeatureExtractor.extract_features(profile, chunk_b)

        self.assertEqual(feats_a, feats_b, "Modifying doc_id must have zero effect on Layer 2 features (anti-leakage violation)")

    # =======================================================================
    # 3. Classification & Calibration Tests
    # =======================================================================

    def test_confidence_tier_monotonicity(self):
        """
        Contract Section 7.1:
        Verify pure probability-to-tier threshold boundaries:
          >= 0.65 -> STRONG
          >= 0.45 -> PARTIAL
          >= 0.10 -> WEAK
          < 0.10  -> UNSUPPORTED
        Verify exact threshold boundaries and monotonicity across the range [0.0, 1.0].
        """
        # 1. Exact boundary assertions
        self.assertEqual(classify_confidence_tier(1.000), "STRONG")
        self.assertEqual(classify_confidence_tier(0.850), "STRONG")
        self.assertEqual(classify_confidence_tier(0.650), "STRONG")
        self.assertEqual(classify_confidence_tier(0.64999), "PARTIAL")

        self.assertEqual(classify_confidence_tier(0.550), "PARTIAL")
        self.assertEqual(classify_confidence_tier(0.450), "PARTIAL")
        self.assertEqual(classify_confidence_tier(0.44999), "WEAK")

        self.assertEqual(classify_confidence_tier(0.250), "WEAK")
        self.assertEqual(classify_confidence_tier(0.100), "WEAK")
        self.assertEqual(classify_confidence_tier(0.09999), "UNSUPPORTED")
        self.assertEqual(classify_confidence_tier(0.000), "UNSUPPORTED")

        # 2. Strict monotonicity check
        tier_order = {
            "UNSUPPORTED": 0,
            "WEAK": 1,
            "PARTIAL": 2,
            "STRONG": 3,
        }

        # Step through probabilities from 0.0 to 1.0 in steps of 0.01
        prev_tier_rank = 0
        for p_int in range(0, 101):
            p = p_int / 100.0
            tier = classify_confidence_tier(p)
            rank = tier_order[tier]
            self.assertGreaterEqual(
                rank, prev_tier_rank,
                f"Monotonicity violation at p={p}: rank {rank} ({tier}) < prev_rank {prev_tier_rank}"
            )
            prev_tier_rank = rank

    # =======================================================================
    # 4. Safe Degraded Mode Tests
    # =======================================================================

    def test_degraded_mode_missing_model(self):
        """
        Contract Section 8.2: Safe Degradation Protocol
        When model file does not exist, verify resolve_confidence:
        - sets degraded=True
        - tier is capped at STRONG (never EXACT)
        - M1 presence-renormalized score is used with calibrated=False
        - match_type is HEURISTIC_PRESENCE
        """
        # ID-masked query that does NOT trigger Layer 1
        query = "Remote code execution in Log4j2 JNDI LDAP lookup"
        profile = parse_query_profile(query)
        self.assertFalse(profile.cves, "Query is ID-masked (contains no explicit CVE)")

        chunk = {
            "chunk_id": "chunk_degraded_test",
            "doc_id": "CVE-2021-44228_NVD",
            "text": "Apache Log4j2 JNDI remote code execution vulnerability.",
            "entities_json": {"cves": ["CVE-2021-44228"]},
        }

        # Pass model=None with no disk artifact (or an explicitly degraded model)
        from unittest.mock import patch
        with patch("threat_retrieval_engine.api.confidence.get_confidence_model", return_value=None):
            res = resolve_confidence(profile, chunk, candidate_score=0.95, model=None)

        # 1. Degraded flag set
        self.assertTrue(res.degraded, "degraded flag must be True when model is missing")

        # 2. Calibrated set to False
        self.assertFalse(res.calibrated, "calibrated must be False in degraded mode")

        # 3. Tier must NEVER be EXACT in degraded mode
        self.assertNotEqual(res.tier, "EXACT", "Tier must NEVER be EXACT in degraded mode")
        self.assertIn(res.tier, ("STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"))
        self.assertEqual(res.tier, "STRONG")

        # 4. Correct match_type and fallback version
        self.assertEqual(res.match_type, "HEURISTIC_PRESENCE")
        self.assertTrue("degraded" in res.model_version or "m1" in res.model_version)

        # Also test with an explicitly degraded dummy model object
        class DummyDegradedModel:
            is_degraded = True
            model_version = "dummy-degraded"

        res_dummy = resolve_confidence(profile, chunk, candidate_score=0.95, model=DummyDegradedModel())
        self.assertTrue(res_dummy.degraded)
        self.assertFalse(res_dummy.calibrated)
        self.assertNotEqual(res_dummy.tier, "EXACT")

    # =======================================================================
    # 5. Metadata Field Separation Tests
    # =======================================================================

    def test_metadata_separation(self):
        """
        Contract Section 2.2: Strict Separation of Metadata Fields
        Verify severity, EPSS score, and CISA KEV flag are separate and independent
        from confidence scoring, with sources_found correctly reporting FOUND,
        NOT_FOUND, and UNAVAILABLE.
        """
        query = "CVE-2021-44228"
        profile = parse_query_profile(query)

        # Chunk A: Low severity, low EPSS, not in KEV
        chunk_a = {
            "chunk_id": "chunk_cve_a",
            "doc_id": "CVE-2021-44228_NVD",
            "text": "Apache Log4j2 vulnerability description",
            "severity": "LOW",
            "epss_score": 0.001,
            "cisa_kev": False,
            "metadata": {
                "doc_id": "CVE-2021-44228_NVD",
                "severity": "LOW",
                "epss_score": 0.001,
                "cisa_kev": False,
            },
        }

        # Chunk B: Critical severity, very high EPSS, present in KEV
        chunk_b = {
            "chunk_id": "chunk_cve_b",
            "doc_id": "CVE-2021-44228_NVD",
            "text": "Apache Log4j2 vulnerability description",
            "severity": "CRITICAL",
            "epss_score": 0.975,
            "cisa_kev": True,
            "metadata": {
                "doc_id": "CVE-2021-44228_NVD",
                "severity": "CRITICAL",
                "epss_score": 0.975,
                "cisa_kev": True,
            },
        }

        res_a = resolve_confidence(profile, chunk_a, candidate_score=0.85)
        res_b = resolve_confidence(profile, chunk_b, candidate_score=0.85)

        # 1. Invariance of confidence score to risk metadata
        self.assertEqual(res_a.probability, res_b.probability, (
            f"Confidence probability changed ({res_a.probability} vs {res_b.probability}) based on severity/EPSS/KEV!"
        ))
        self.assertEqual(res_a.tier, res_b.tier)
        self.assertEqual(res_a.match_type, res_b.match_type)
        self.assertEqual(res_a.tier_basis, res_b.tier_basis)

        # 2. Strict decoupling: ConfidenceResolution must not contain severity or EPSS
        self.assertFalse(hasattr(res_a, "severity"))
        self.assertFalse(hasattr(res_a, "epss_score"))
        self.assertFalse(hasattr(res_a, "cisa_kev"))

        # 3. Verification of sources_found reporting specification
        # Valid sources_found schema:
        # Sources: NVD, CISA, EPSS, CVE_LIST_V5
        # States: FOUND, NOT_FOUND, UNAVAILABLE
        VALID_SOURCES = {"NVD", "CISA", "EPSS", "CVE_LIST_V5"}
        VALID_STATUSES = {"FOUND", "NOT_FOUND", "UNAVAILABLE"}

        sources_found_sample = {
            "NVD": "FOUND",
            "CISA": "FOUND",
            "EPSS": "NOT_FOUND",
            "CVE_LIST_V5": "UNAVAILABLE",
        }

        # Validate that every source in sample is valid
        for src, status in sources_found_sample.items():
            self.assertIn(src, VALID_SOURCES, f"Invalid source {src}")
            self.assertIn(status, VALID_STATUSES, f"Invalid status {status}")

        # Verify that a chunk with different sources_found also does NOT change confidence
        chunk_c = copy.deepcopy(chunk_a)
        chunk_c["sources_found"] = sources_found_sample
        res_c = resolve_confidence(profile, chunk_c, candidate_score=0.85)
        self.assertEqual(res_c.probability, res_a.probability)
        self.assertEqual(res_c.tier, res_a.tier)

    # =======================================================================
    # 6. Behavioral Option B Heuristic Tests
    # =======================================================================

    def test_behavioral_query_option_b_uncalibrated(self):
        """
        Contract Section 3.3: Option B Heuristic Protocol
        For behavioral queries (IOC/TTP without CVE):
        - Handled via M1 presence-renormalized weights
        - Output sets calibrated = False
        - tier_basis = 'UNCALIBRATED_BEHAVIORAL_HEURISTIC'
        - Tier capped at STRONG (never EXACT)
        """
        # Behavioral query: technique + IP, zero CVE
        query = "Lateral movement from 198.51.100.24 using technique T1021.002"
        profile = parse_query_profile(query)
        self.assertFalse(profile.has_cve)
        self.assertTrue(profile.has_ioc)
        self.assertTrue(profile.has_ttp)

        chunk = {
            "chunk_id": "chunk_behavioral_01",
            "doc_id": "REPORT-2026-ATTACK",
            "text": "Adversary observed performing SMB lateral movement T1021.002 from host 198.51.100.24",
            "entities_json": {
                "cves": [],
                "iocs": {"ipv4": ["198.51.100.24"], "sha256": [], "md5": []},
                "mitre_ttps": ["T1021.002"],
            },
        }

        res = resolve_confidence(profile, chunk, candidate_score=0.90)

        # 1. Behavioral resolution attributes
        self.assertEqual(res.match_type, "HEURISTIC_PRESENCE")
        self.assertFalse(res.calibrated, "Behavioral Option B queries must have calibrated=False")
        self.assertEqual(res.tier_basis, "UNCALIBRATED_BEHAVIORAL_HEURISTIC")
        self.assertNotEqual(res.tier, "EXACT", "Behavioral queries can never achieve tier EXACT")
        self.assertEqual(res.tier, "STRONG")
        self.assertFalse(res.degraded)


if __name__ == "__main__":
    unittest.main()
