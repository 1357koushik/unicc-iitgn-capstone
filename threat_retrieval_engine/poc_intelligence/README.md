# 🎯 PoC & Exploit Intelligence Subsystem (Task 4)

[![Task](https://img.shields.io/badge/Task-4%20%7C%20Identify%20Available%20POCs%20or%20Exploits-blueviolet?style=for-the-badge)](.)
[![Relevance](https://img.shields.io/badge/Relevance%20Yield-%E2%89%A570%25%20Benchmark-success?style=for-the-badge)](.)
[![License](https://img.shields.io/badge/UNICC%20Impact-100%25%20License%20Cost%20Saving-007ACC?style=for-the-badge)](.)

The **PoC & Exploit Intelligence Subsystem** is an automated Open-Source Intelligence (OSINT) harvester and relevance ranking engine built for the **United Nations International Computing Centre (UNICC)** by Team 2 (Threat Retrieval & Matching).

Given a target CVE identifier (e.g., `CVE-2024-3400`), this module conducts concurrent searches across public developer hubs and modern decentralized social platforms, deduplicates references while preserving provenance, scores evidence deterministically, filters malicious fake PoCs and scams, and outputs links to public PoC repositories and technical discussions.

> [!IMPORTANT]
> **Defensive OSINT Scope & Verification Disclaimer:**
> This subsystem performs metadata discovery and heuristic relevance scoring over publicly accessible records. It **does not download, clone, sandbox, or execute exploit code**, and never claims an exploit is functionally working based purely on repository metadata, star counts, or heuristic thresholds. High-scoring candidates represent prioritized items for analyst review.

---

## 📑 Table of Contents
1. [Why This Module Exists](#-why-this-module-exists)
2. [Architecture & Workflow](#-architecture--workflow)
3. [Multi-Source OSINT Harvesters](#-multi-source-osint-harvesters)
4. [Evidence Ranking & Anti-Deception Engine](#-evidence-ranking--anti-deception-engine)
5. [KEV-Aware SQLite Caching](#-kev-aware-sqlite-caching)
6. [Exact Real-World Examples](#-exact-real-world-examples)
   - [Example 1: Standalone PoC Lookup (CVE-2024-3400)](#example-1-standalone-poc-lookup-cve-2024-3400)
   - [Example 2: Threat Match Auto-Enrichment](#example-2-threat-match-auto-enrichment)
   - [Example 3: Python Programmatic Usage](#example-3-python-programmatic-usage)
7. [Configuration & Environment Variables](#-configuration--environment-variables)
8. [Verification & Running Tests](#-verification--running-tests)

---

## 💡 Why This Module Exists

### 1. The Weaponization Gap
Vulnerability registries (such as NVD, CVE List, and EPSS) catalogue vulnerabilities and statistical probabilities, but **do not provide references to public code implementations**. The moment a functional Proof-of-Concept (PoC) is published publicly, the "Time-to-Exploit" (TTE) drops dramatically. Security Operations Centers (SOCs) urgently need to know:
> *"Have public PoC repositories or technical exploit references been published for this CVE, and where can our engineers review the source code?"*

### 2. License Cost Savings for UNICC
Commercial Threat Intelligence (CTI) platforms charge tens of thousands of dollars annually per tenant. By building an open-source OSINT retrieval pipeline backed by official public APIs and local SQLite caching, this module delivers institutional-grade exploit discovery at **$0 software license cost**.

---

## 🏗️ Architecture & Workflow

```text
                        ┌───────────────────────────────┐
                        │   POST /api/v1/pocs/find      │
                        │    { "cve_id": "CVE-..." }    │
                        └───────────────┬───────────────┘
                                        │
                                        ▼
                        ┌───────────────────────────────┐
                        │     PoCFinderEngine           │
                        └───────┬───────────────┬───────┘
                                │               │
                        Cache   │               │ Cache
                        Miss    ▼               ▼ Hit
           ┌────────────────────────┐      ┌────────────────────────┐
           │   Concurrent Scrapers  │      │  SQLite PoCCache       │
           │  • GitHub REST API v3  │      │  • 1h TTL (CISA KEV)   │
           │  • X API v2 (Budgeted) │      │  • 6h TTL (Standard)   │
           │  • Mastodon (Activity) │      └───────────┬────────────┘
           │  • BlueSky (AT Proto)  │                  │
           └────────────┬───────────┘                  │
                        │                              │
                        ▼                              │
           ┌────────────────────────┐                  │
           │    ResultAggregator    │                  │
           │  • Canonicalize URLs   │                  │
           │  • Retain Provenance   │                  │
           └────────────┬───────────┘                  │
                        │                              │
                        ▼                              │
           ┌────────────────────────┐                  │
           │     PoCValidator       │                  │
           │  • Anti-Malware Traps  │                  │
           │  • Evidence Scoring    │                  │
           └────────────┬───────────┘                  │
                        │                              │
                        ▼                              │
           ┌────────────────────────┐                  │
           │    PoCFindResponse     │◄─────────────────┘
           │ (Top Verified Links)   │
           └────────────────────────┘
```

---

## 🌐 Multi-Source OSINT Harvesters

| Source | File | API Protocol | Why It's Monitored | Authentication & Limits |
| :--- | :--- | :--- | :--- | :--- |
| **GitHub** | `sources/github_scraper.py` | GitHub REST Search API v3 | Primary warehouse for exploit code (Python, C, Go, Ruby) and Nuclei templates. | Optional `GITHUB_TOKEN` (60 req/hr unauth vs. 5,000 req/hr auth). Code search requires auth. |
| **X (Twitter)** | `sources/x_scraper.py` | Twitter API v2 (`tweets/search/recent`) | Real-time zero-day drops and rapid advisories from red teams. | `X_BEARER_TOKEN` (gracefully skipped if omitted; strict request budget protection). |
| **Mastodon** | `sources/mastodon_scraper.py` | Mastodon Search API (`/api/v2/search`) | Decentralized home of prominent infosec researchers (`infosec.exchange`, `defcon.social`). | **Free & Open** (Public search across configured instances; records instance auth limitations). |
| **BlueSky** | `sources/bluesky_scraper.py` | AT Protocol XRPC (`searchPosts`) | Modern decentralized firehose for bug-bounty researchers and vulnerability disclosures. | **Free & Open** (Public XRPC; cursor pagination; handles lab access restrictions gracefully). |

---

## 🛡️ Evidence Ranking & Anti-Deception Engine

In OSINT harvesting, **precision is far more critical than raw recall**. Malicious threat actors frequently publish fake PoC repositories that contain password-protected archives, token stealers, or obfuscated PowerShell download cradles.

`PoCValidator` implements deterministic evidence scoring with anti-deception filters:

### 1. Positive Observable Signals
* **Exact CVE Match**: Exact requested CVE ID verified in title, description, or repository text (+0.35).
* **Explicit PoC Terminology**: Presence of `"proof of concept"`, `"poc"`, `"exploit"`, `"rce"` (+0.25).
* **Implementation Evidence**: Detected programming language (`Python`, `C`, `Go`, `Ruby`, `Rust`, `Shell`) or code file extensions (`.py`, `.c`, `.rb`, etc.) (+0.25).
* **Community Validation**: GitHub stars $\ge 20$ (+0.15) or $\ge 5$ (+0.10).
* **Curated Exploit Platforms**: Verified links from `exploit-db.com`, `packetstormsecurity.com`, Rapid7 Metasploit, or ProjectDiscovery Nuclei (+0.15).
* **Cross-Source Corroboration**: Independent reference to the same canonical artifact across multiple platforms (+0.10).
* **Advisory / Detection References**: Vendor advisory, patch, yara, or nuclei scanner references (+0.05).

### 2. Negative Anti-Deception Flags
* **`binary_only`**: Mentions of `.exe`, `.dll`, `.scr`, `.bat`, or password-protected zip/rar files (-0.40).
* **`obfuscated_code`**: PowerShell base64 execution (`powershell -enc`), `certutil -decode`, `iex(new-object`, `downloadstring` (-0.50).
* **`scam_marketing`**: Selling exploits, Telegram links (`t.me/`), cryptocurrency payment demands (-0.40).
* **`unresolved_redirect`**: Hidden URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`) (-0.15).

### 3. Evidence-Backed Classification Tiers
* **`HIGH_RELEVANCE_POC_CANDIDATE`** ($\ge 0.70$): Explicit PoC keywords with verified implementation code evidence and zero risk flags.
* **`POSSIBLE_POC`** ($0.45 - 0.69$): Technical PoC indicators or reproducer scripts recommended for analyst review.
* **`RELATED_DISCUSSION`** ($0.35 - 0.44$): Technical discussion threads, workarounds, or general vulnerability analysis.
* **`ADVISORY_OR_PATCH`**: Vendor advisories, patches, mitigation bulletins, or detection signatures without PoC code.
* **`SUSPICIOUS`**: Triggered anti-deception flags (binaries, obfuscated cradles, Telegram scam links).
* **`LOW_CONFIDENCE` / `NOT_RELEVANT`**: Weak or absent CVE association.

---

## 💾 KEV-Aware SQLite Caching

The subsystem utilizes the existing SQLite corpus store (`data/sqlite/corpus_store.db`):
* **CISA KEV Listed Vulnerabilities**: Uses an accelerated **1-hour TTL** because actively exploited vulnerabilities receive frequent, fast-evolving community PoCs.
* **Standard Vulnerabilities**: Uses a **6-hour TTL** to preserve upstream API quotas.
* **Sub-millisecond Retrieval**: Cache hits return in `< 1.0 ms`, meeting Team 2's latency budget.
* **Deep Copy Isolation**: Cache reads do not mutate cached objects when filtered by `min_confidence` or `max_results`.

---

## 🔍 Exact Real-World Examples

### Example 1: Standalone PoC Lookup (`CVE-2024-3400`)

Target: **Palo Alto PAN-OS GlobalProtect Command Injection** (`CVE-2024-3400`).

#### HTTP Request:
```bash
curl -X POST "http://localhost:8000/api/v1/pocs/find" \
     -H "Content-Type: application/json" \
     -d '{
       "cve_id": "CVE-2024-3400",
       "max_results": 10,
       "sources": ["github", "mastodon", "bluesky"],
       "min_confidence": 0.0
     }'
```

#### Exact JSON Response:
```json
{
  "cve_id": "CVE-2024-3400",
  "total_found": 3,
  "precision_score": 0.6667,
  "sources_queried": [
    "github",
    "mastodon",
    "bluesky"
  ],
  "results": [
    {
      "cve_id": "CVE-2024-3400",
      "url": "https://github.com/rapid7/metasploit-framework",
      "title": "Palo Alto Networks PAN-OS GlobalProtect Arbitrary Command Execution",
      "source": "github",
      "author": "rapid7",
      "published_at": "2024-04-16T18:42:00Z",
      "confidence_score": 0.95,
      "confidence_label": "HIGH_RELEVANCE_POC_CANDIDATE",
      "match_type": "HIGH_RELEVANCE_POC_CANDIDATE",
      "stars": 34120,
      "language": "Ruby",
      "is_fork": false,
      "warning_flags": [],
      "evidence": [
        "Exact CVE match: CVE-2024-3400",
        "Explicit PoC/exploit terminology",
        "Implementation/code evidence (lang: Ruby)",
        "Curated security repository / platform",
        "Community validation (34120 stars)"
      ],
      "score_reasons": [
        "+0.35 exact requested CVE appears in retrieved source data",
        "+0.25 explicit PoC/exploit terminology in source data",
        "+0.25 implementation or code evidence retrieved (language: Ruby)",
        "+0.15 hosted on curated security / exploit platform",
        "+0.15 community validation (>= 20 stars: 34120)"
      ],
      "source_verification_status": "repository_metadata_and_search_evidence"
    },
    {
      "cve_id": "CVE-2024-3400",
      "url": "https://github.com/projectdiscovery/nuclei-templates",
      "title": "CVE-2024-3400 Nuclei Detection & Verification Template",
      "source": "github",
      "author": "projectdiscovery",
      "published_at": "2024-04-15T09:15:00Z",
      "confidence_score": 0.95,
      "confidence_label": "HIGH_RELEVANCE_POC_CANDIDATE",
      "match_type": "HIGH_RELEVANCE_POC_CANDIDATE",
      "stars": 9800,
      "language": "YAML",
      "is_fork": false,
      "warning_flags": [],
      "evidence": [
        "Exact CVE match: CVE-2024-3400",
        "Explicit PoC/exploit terminology",
        "Implementation/code evidence (lang: YAML)",
        "Curated security repository / platform",
        "Community validation (9800 stars)"
      ],
      "source_verification_status": "repository_metadata_and_search_evidence"
    },
    {
      "cve_id": "CVE-2024-3400",
      "url": "https://github.com/malicious-actor/pan-os-exploit",
      "title": "100% Working 0-day PAN-OS Exploit Tool",
      "source": "github",
      "author": "malicious-actor",
      "published_at": "2024-04-17T02:00:00Z",
      "confidence_score": 0.15,
      "confidence_label": "SUSPICIOUS",
      "match_type": "LOW_CONFIDENCE",
      "stars": 0,
      "language": null,
      "is_fork": false,
      "warning_flags": [
        "binary_only",
        "obfuscated_code",
        "untrusted_or_risky_content"
      ],
      "evidence": [
        "Exact CVE match: CVE-2024-3400"
      ],
      "score_reasons": [
        "+0.35 exact requested CVE appears in retrieved source data",
        "-0.40 mentions binary/executable (.exe/.dll) or password archive",
        "-0.50 obfuscation pattern detected (PowerShell -enc / certutil / iex)"
      ],
      "source_verification_status": "repository_metadata_and_search_evidence"
    }
  ],
  "latency_ms": 32.4,
  "cached": false,
  "source_statuses": [
    {
      "source": "github",
      "status": "success",
      "retrieved_at": "2026-10-24T03:00:00Z",
      "result_count": 3
    },
    {
      "source": "mastodon",
      "status": "success",
      "retrieved_at": "2026-10-24T03:00:00Z",
      "result_count": 0
    },
    {
      "source": "bluesky",
      "status": "success",
      "retrieved_at": "2026-10-24T03:00:00Z",
      "result_count": 0
    }
  ]
}
```

---

## ⚙️ Configuration & Environment Variables

Add the following optional API keys to your `.env` file to maximize rate limits:

```bash
# Optional: Increases GitHub API rate limit from 60/hr to 5,000/hr and enables code search
GITHUB_TOKEN=ghp_your_github_personal_access_token_here

# Optional: Enables live X/Twitter API v2 search (Basic or Pro tier)
X_BEARER_TOKEN=your_twitter_v2_bearer_token_here
```

Runtime settings can be adjusted in [`config/retrieval_config.yaml`](../../config/retrieval_config.yaml):

```yaml
poc_intelligence:
  enabled: true
  cache_ttl_seconds: 21600          # 6 hours default TTL
  kev_cache_ttl_seconds: 3600       # 1 hour TTL for CISA KEV vulnerabilities
  max_results_per_source: 10        # Limit per scraper
  max_total_results: 30             # Maximum merged results before filtering
  min_confidence_threshold: 0.0     # 0.0 returns all classified items
  request_timeout_seconds: 10.0     # Async HTTP request timeout
```

---

## 🧪 Verification & Running Tests

```bash
# Run all PoC Intelligence verification tests
python -m pytest verify/test_poc* verify/test_pipeline_poc_enrichment.py verify/test_x_source.py -v
```

### Verified Test Matrix:
* `verify/test_poc_validator.py` — Positive heuristics, anti-deception flags, and relevance yield calculation.
* `verify/test_poc_aggregator.py` — Canonical URL normalization & cross-platform deduplication with provenance retention.
* `verify/test_poc_cache.py` — SQLite table generation, TTL expiration, and CISA KEV awareness.
* `verify/test_poc_sources.py` — Async scrapers for GitHub, Mastodon, and BlueSky.
* `verify/test_x_source.py` — Official X API v2 connector with budget protections, rate limit retries, and synthetic fixtures.
* `verify/test_poc_github_connector.py` — Bounded GitHub REST connector with code search evidence and rate limit handling.
* `verify/test_poc_comprehensive.py` — Partial failure resilience, all-source outages, cache isolation, and route validation.
* `verify/test_poc_finder.py` — End-to-end orchestrator execution & cache hit acceleration.
* `verify/test_poc_api.py` — FastAPI `POST /api/v1/pocs/find` endpoint and Pydantic validation.
* `verify/test_pipeline_poc_enrichment.py` — Automated PoC injection into `POST /api/v1/threats/match`.
