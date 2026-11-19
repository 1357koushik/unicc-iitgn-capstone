"""
Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Synthesizes retrieved historical records into a calibrated threat triage report.
"""

from typing import Any, Dict, List, Optional, Union
import json
import re
import urllib.request
import urllib.error
from ..gateway.interface import LLMProvider
from ..schemas.investigation import InvestigationResult
from ..prompts.investigation_prompts import INVESTIGATION_SYSTEM_PROMPT, build_investigation_prompt

# Longest question the retrieval API accepts (MatchRequest.query, threat_retrieval_engine/api/schemas.py).
MAX_QUERY_CHARS = 4096


class RetrievalUnavailableError(Exception):
    """The threat retrieval service could not search (not reachable, still starting, or an error).
    Not an "empty result": an investigation must not report "no match" when no search ran."""


def normalize_team2_evidence(raw_evidence: Any) -> List[Dict[str, Any]]:
    """
    Translates raw retrieval engine responses into a clean, normalized evidence schema.
    Handles top_matches, supporting_evidence_chunks, dictionaries, and Pydantic models.
    Preserves all supporting document citations instead of arbitrarily truncating to citations[0].
    """
    if not raw_evidence:
        return []

    # If already a list of dicts with document_id and content, return directly
    if isinstance(raw_evidence, list) and all(isinstance(x, dict) and "document_id" in x for x in raw_evidence):
        return raw_evidence

    # If wrapped in a dict with top_matches (standard /threats/match payload)
    if isinstance(raw_evidence, dict) and "top_matches" in raw_evidence:
        raw_evidence = raw_evidence["top_matches"]

    normalized = []
    for item in raw_evidence:
        if isinstance(item, dict):
            chunk_id = item.get("chunk_id") or item.get("id") or "EVIDENCE"
            score = (
                item.get("composite_score")
                if item.get("composite_score") is not None
                else (item.get("relevance_score") if item.get("relevance_score") is not None else 0.0)
            )
            citations = item.get("citations", [])
            stix = item.get("stix_relationships", [])
            tier = item.get("confidence_tier")
            attr = item.get("attribution", {})
            breakdown = item.get("evidence_breakdown", {})

            if citations and isinstance(citations, list) and len(citations) > 0:
                for cit in citations:
                    if isinstance(cit, dict):
                        doc_id = cit.get("doc_id") or cit.get("document_id") or chunk_id
                        content = cit.get("text_snippet") or cit.get("content") or item.get("text", "")
                        source = cit.get("source_org", "Knowledge Base")
                    else:
                        doc_id = getattr(cit, "doc_id", chunk_id)
                        content = getattr(cit, "text_snippet", item.get("text", ""))
                        source = getattr(cit, "source_org", "Knowledge Base")
                    normalized.append({
                        "document_id": str(doc_id),
                        "relevance_score": float(score),
                        "content": str(content).strip(),
                        "source": str(source),
                        "confidence_tier": tier,
                        "stix_relationships": stix,
                        "attribution": attr,
                        "evidence_breakdown": breakdown,
                    })
            else:
                doc_id = item.get("document_id") or chunk_id
                content = item.get("content") or item.get("text") or ""
                source = item.get("source", "Knowledge Base")
                normalized.append({
                    "document_id": str(doc_id),
                    "relevance_score": float(score),
                    "content": str(content).strip(),
                    "source": str(source),
                    "confidence_tier": tier,
                    "stix_relationships": stix,
                    "attribution": attr,
                    "evidence_breakdown": breakdown,
                })

        else:
            chunk_id = getattr(item, "chunk_id", "EVIDENCE")
            score = (
                getattr(item, "composite_score")
                if getattr(item, "composite_score", None) is not None
                else (getattr(item, "relevance_score", 0.0) if getattr(item, "relevance_score", None) is not None else 0.0)
            )
            citations = getattr(item, "citations", [])
            stix = getattr(item, "stix_relationships", [])
            tier = getattr(item, "confidence_tier", None)
            attr = getattr(item, "attribution", {})
            breakdown = getattr(item, "evidence_breakdown", {})

            if citations and len(citations) > 0:
                for cit in citations:
                    doc_id = getattr(cit, "doc_id", chunk_id)
                    content = getattr(cit, "text_snippet", getattr(item, "text", ""))
                    source = getattr(cit, "source_org", "Knowledge Base")
                    normalized.append({
                        "document_id": str(doc_id),
                        "relevance_score": float(score),
                        "content": str(content).strip(),
                        "source": str(source),
                        "confidence_tier": tier,
                        "stix_relationships": stix,
                        "attribution": attr,
                        "evidence_breakdown": breakdown,
                    })
            else:
                doc_id = getattr(item, "document_id", chunk_id)
                content = getattr(item, "content", getattr(item, "text", ""))
                source = getattr(item, "source", "Knowledge Base")
                normalized.append({
                    "document_id": str(doc_id),
                    "relevance_score": float(score),
                    "content": str(content).strip(),
                    "source": str(source),
                    "confidence_tier": tier,
                    "stix_relationships": stix,
                    "attribution": attr,
                    "evidence_breakdown": breakdown,
                })

    return normalized


class ThreatInvestigator:
    """Encapsulates RAG-based threat investigation and evidence grounding."""

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def fetch_retrieval_evidence(
        self,
        observation: str,
        api_url: str = "http://localhost:8000",
        top_k: int = 5,
        allowed_sources: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Directly queries the Threat Retrieval & Matching REST API.
        """
        endpoint = f"{api_url.rstrip('/')}/api/v1/threats/match"
        payload = {
            # The retrieval API takes at most MAX_QUERY_CHARS characters and refuses longer
            # questions; a long pasted report is searched on its beginning.
            "query": observation[:MAX_QUERY_CHARS],
            "top_k": top_k,
            "alpha": 0.5,
            "include_pocs": False,
        }
        if allowed_sources:
            payload["allowed_sources"] = allowed_sources

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        # If the search did not run, say so. Returning no evidence here would make the
        # investigation report "no matching records" - a false all-clear.
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 503:
                reason = "it is busy or still starting (HTTP 503)"
            else:
                reason = f"it answered HTTP {e.code}"
            raise RetrievalUnavailableError(f"The threat retrieval service at {endpoint} did not search: {reason}.")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise RetrievalUnavailableError(f"The threat retrieval service at {endpoint} cannot be reached: {reason}.")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise RetrievalUnavailableError(f"The threat retrieval service at {endpoint} sent an answer that is not JSON.")
        return normalize_team2_evidence(result)

    def investigate(
        self,
        observation: str,
        retrieved_evidence: Optional[Any] = None,
        team2_api_url: Optional[str] = None,
        allowed_sources: Optional[List[str]] = None,
    ) -> InvestigationResult:
        """
        Executes an evidence-grounded threat investigation.
        """
        if not observation or not observation.strip():
            raise ValueError("Observation text cannot be empty.")

        # If live retrieval URL is provided, query it automatically
        if team2_api_url and not retrieved_evidence:
            clean_evidence = self.fetch_retrieval_evidence(
                observation,
                api_url=team2_api_url,
                allowed_sources=allowed_sources
            )
        else:
            clean_evidence = normalize_team2_evidence(retrieved_evidence)

        # Honest fallback: if zero evidence was returned by the knowledge base,
        # return an honest Unsupported triage verdict instead of letting the LLM hallucinate.
        if not clean_evidence:
            fallback_data = {
                "query_observation": observation.strip(),
                "match_status": "Unsupported",
                "assessment_narrative": (
                    "No matching historical threat intelligence records were found in the knowledge base "
                    "for the observed indicators or activity. No correlation with known campaigns or threat actors."
                ),
                "potential_threat_actors": [],
                "associated_malware": [],
                "associated_cves": [],
                "mitre_tactics": [],
                "associated_mitre_tactics": [],
                "patch_details": {
                    "patch_status": "Not Applicable",
                    "affected_versions": [],
                    "fixed_versions": [],
                    "remediation_workarounds": ["No active historical threat match requiring patch remediation."]
                },
                "confidence_level": "Low",
                "supporting_citations": [],
                "investigator_notes": "Human analyst review recommended. Zero verified corpus matches identified."
            }
            if hasattr(InvestigationResult, "model_validate"):
                return InvestigationResult.model_validate(fallback_data)
            return InvestigationResult(**fallback_data)

        prompt = build_investigation_prompt(observation, clean_evidence)

        result: InvestigationResult = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=InvestigationResult,
            system_prompt=INVESTIGATION_SYSTEM_PROMPT,
        )

        # Post-validation check: Harmonize and resolve citations to real document IDs
        # Prevents brittle string-equality failures when LLM cites 'EVIDENCE #1' or base CVE
        doc_id_map: Dict[str, str] = {}
        for idx, doc in enumerate(clean_evidence, 1):
            real_id = doc.get("document_id", "")
            if real_id:
                doc_id_map[real_id.lower()] = real_id
                doc_id_map[f"evidence #{idx}".lower()] = real_id
                doc_id_map[f"evidence {idx}".lower()] = real_id
                doc_id_map[f"evidence-{idx}".lower()] = real_id
                doc_id_map[f"doc-{idx}".lower()] = real_id
                doc_id_map[f"doc #{idx}".lower()] = real_id
                doc_id_map[f"doc {idx}".lower()] = real_id
                # Zero-padded support: DOC-01, DOC-001, doc01, doc001
                doc_id_map[f"doc-{idx:02d}".lower()] = real_id
                doc_id_map[f"doc-{idx:03d}".lower()] = real_id
                doc_id_map[f"doc{idx}".lower()] = real_id
                doc_id_map[f"doc{idx:02d}".lower()] = real_id
                doc_id_map[f"doc{idx:03d}".lower()] = real_id
                doc_id_map[f"evidence-{idx:02d}".lower()] = real_id
                doc_id_map[f"evidence-{idx:03d}".lower()] = real_id
                doc_id_map[str(idx)] = real_id
                # Only set base_cve if not already mapped to avoid collision overwrites
                base_cve = real_id.split("_")[0].lower()
                if base_cve.startswith("cve-") and base_cve not in doc_id_map:
                    doc_id_map[base_cve] = real_id

        for citation in result.supporting_citations:
            raw_cid = (citation.document_id or "").strip().lower()
            clean_cid = re.sub(r"^(source|citation|ref)[:\s#]+", "", raw_cid).strip()
            if raw_cid in doc_id_map:
                citation.document_id = doc_id_map[raw_cid]
            elif clean_cid in doc_id_map:
                citation.document_id = doc_id_map[clean_cid]
            else:
                citation.key_excerpt = f"[Unverified Citation: {citation.document_id}] {citation.key_excerpt}"

        return result
