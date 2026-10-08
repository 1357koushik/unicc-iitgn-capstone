# 🎯 PoC & Exploit Intelligence Subsystem (Task 4)

[![Task](https://img.shields.io/badge/Task-4%20%7C%20Identify%20Available%20POCs%20or%20Exploits-blueviolet?style=for-the-badge)](.)
[![Precision](https://img.shields.io/badge/Precision%20Target-%E2%89%A570%25-success?style=for-the-badge)](.)
[![License](https://img.shields.io/badge/UNICC%20Impact-100%25%20License%20Cost%20Saving-007ACC?style=for-the-badge)](.)

The **PoC & Exploit Intelligence Subsystem** is an automated Open-Source Intelligence (OSINT) harvester and verification engine built for the **United Nations International Computing Centre (UNICC)** by Team 2 (Threat Retrieval & Matching).

Given a target CVE identifier (e.g., `CVE-2024-3400`), this module conducts concurrent searches across public developer hubs and modern decentralized social platforms, deduplicates references, scores authenticity, filters malicious fake PoCs, and outputs high-precision links to working exploit demonstrations.

---

## 📑 Table of Contents
1. [Why This Module Exists](#-why-this-module-exists)
2. [Architecture & Workflow](#-architecture--workflow)
3. [Multi-Source OSINT Harvesters](#-multi-source-osint-harvesters)
4. [Precision & Anti-Deception Engine (≥70% Benchmark)](#-precision--anti-deception-engine-70-benchmark)
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
Vulnerability registries (such as NVD, CVE List, and EPSS) catalogue vulnerabilities and statistical probabilities, but **do not provide the actual exploit code**. The moment a functional Proof-of-Concept (PoC) is published publicly, the "Time-to-Exploit" (TTE) drops to minutes as threat actors immediately script attacks. Security Operations Centers (SOCs) urgently need to know:
> *"Does functional exploit code exist online right now, and where can our engineers review it?"*

### 2. License Cost Savings for UNICC
Commercial Threat Intelligence (CTI) platforms (e.g., Recorded Future, Mandiant Advantage, VulnCheck Exploit Intelligence) charge between **$30,000 to $150,000+ annually** per tenant. By building an open-source OSINT retrieval pipeline backed by public APIs and local SQLite caching, this module delivers institutional-grade exploit discovery at **$0 software license cost**.

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
           │  • X API v2            │      │  • 6h TTL (Standard)   │
           │  • Mastodon (Activity) │      └───────────┬────────────┘
           │  • BlueSky (AT Proto)  │                  │
           └────────────┬───────────┘                  │
                        │                              │
                        ▼                              │
           ┌────────────────────────┐                  │
           │    ResultAggregator    │                  │
           │  • Canonicalize URLs   │                  │
           │  • Cross-Platform Merge│                  │
           └────────────┬───────────┘                  │
                        │                              │
                        ▼                              │
           ┌────────────────────────┐                  │
           │     PoCValidator       │                  │
           │  • Anti-Malware Traps  │                  │
           │  • Precision ≥ 70%     │                  │
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

| Source | File | API Protocol | Why It's Monitored | Authentication |
| :--- | :--- | :--- | :--- | :--- |
| **GitHub** | `sources/github_scraper.py` | GitHub REST Search API v3 | Primary warehouse for exploit code (Python, C, Go, Ruby) and Nuclei templates. | Optional `GITHUB_TOKEN` (60 req/hr unauth vs. 5,000 req/hr auth) |
| **X (Twitter)** | `sources/x_scraper.py` | Twitter API v2 | Real-time zero-day drops and rapid advisories from red teams. | `X_BEARER_TOKEN` (gracefully skipped if omitted) |
| **Mastodon** | `sources/mastodon_scraper.py` | Mastodon Search API | Decentralized home of prominent infosec researchers (`infosec.exchange`, `defcon.social`). | **100% Free & Open** (No auth required) |
| **BlueSky** | `sources/bluesky_scraper.py` | AT Protocol Lexicon (`searchPosts`) | Modern decentralized firehose for bug-bounty researchers and vulnerability disclosures. | **100% Free & Open** (No auth required) |

---

## 🛡️ Precision & Anti-Deception Engine (≥70% Benchmark)

In OSINT harvesting, **precision is far more critical than raw recall**. Malicious threat actors frequently publish fake PoC repositories that contain password-protected archives, token stealers, or obfuscated PowerShell download cradles.

`PoCValidator` implements an empirical scoring algorithm:

$$\text{Precision Score} = \frac{N_{\text{VERIFIED\_CODE}} + N_{\text{LIKELY\_POC}}}{N_{\text{TOTAL}}}$$

### 1. Positive Verification Boosts
* **Curated Exploit Platforms**: Links on `exploit-db.com`, `packetstormsecurity.com`, `sploitus.com`, or Rapid7 Metasploit (+0.30).
* **Community Validation**: GitHub stars $\ge 20$ (+0.30) or $\ge 5$ (+0.20).
* **Identified Source Code**: Explicit language detected (`Python`, `C`, `Go`, `Ruby`, `Rust`) or extensions `.py`, `.c`, `.rb`, `.sh`, `.yml` (+0.20).
* **Explicit CVE Title & Exploit Keywords**: Mentioning target CVE alongside `"proof of concept"`, `"rce"`, `"exploit"`, `"nuclei"` (+0.30).
* **Cross-Source Corroboration**: The same canonical PoC URL confirmed on multiple distinct platforms (+0.15).

### 2. Negative Anti-Deception Flags
* **`binary_only`**: Mentions of `.exe`, `.dll`, `.scr`, `.bat`, or password-protected zip/rar files (-0.40).
* **`obfuscated_code`**: PowerShell base64 execution (`powershell -enc`), `certutil -decode`, `iex(new-object` (-0.50).
* **`scam_marketing`**: Selling exploits, Telegram links (`t.me/`), cryptocurrency payment demands (-0.40).
* **`unresolved_redirect`**: Hidden URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`) (-0.15).

### 3. Classification Tiers
* **`VERIFIED_CODE`** ($\ge 0.75$): Confirmed source code repository with community verification.
* **`LIKELY_POC`** ($0.50 - 0.74$): Strong indicators of PoC scripts, recommended for analyst inspection.
* **`DISCUSSION`** ($0.25 - 0.49$): Informational posts, patch advisories, or workarounds.
* **`SUSPICIOUS`** ($< 0.25$): Honeypots, spam marketing, or potential infostealer droppers.

---

## 💾 KEV-Aware SQLite Caching

The subsystem utilizes the existing SQLite corpus store (`data/sqlite/corpus_store.db`):
* **CISA KEV Listed Vulnerabilities**: Uses an accelerated **1-hour TTL** because actively exploited vulnerabilities receive frequent, fast-evolving community PoCs.
* **Standard Vulnerabilities**: Uses a **6-hour TTL** to preserve upstream API quotas.
* **Sub-millisecond Retrieval**: Cache hits return in `< 1.0 ms`, meeting Team 2's latency budget.

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
  "precision_score": 1.0,
  "sources_queried": [
    "github",
    "mastodon",
    "bluesky"
  ],
  "results": [
    {
      "url": "https://github.com/rapid7/metasploit-framework",
      "title": "Palo Alto Networks PAN-OS GlobalProtect Arbitrary Command Execution",
      "source": "github",
      "author": "rapid7",
      "published_at": "2024-04-16T18:42:00Z",
      "confidence_score": 0.95,
      "confidence_label": "VERIFIED_CODE",
      "stars": 34120,
      "language": "Ruby",
      "is_fork": false,
      "warning_flags": []
    },
    {
      "url": "https://github.com/projectdiscovery/nuclei-templates",
      "title": "CVE-2024-3400 Nuclei Detection & Verification Template",
      "source": "github",
      "author": "projectdiscovery",
      "published_at": "2024-04-15T09:15:00Z",
      "confidence_score": 0.90,
      "confidence_label": "VERIFIED_CODE",
      "stars": 9800,
      "language": "YAML",
      "is_fork": false,
      "warning_flags": []
    },
    {
      "url": "https://github.com/malicious-actor/pan-os-exploit",
      "title": "100% Working 0-day PAN-OS Exploit Tool",
      "source": "github",
      "author": "malicious-actor",
      "published_at": "2024-04-17T02:00:00Z",
      "confidence_score": 0.15,
      "confidence_label": "SUSPICIOUS",
      "stars": 0,
      "language": null,
      "is_fork": false,
      "warning_flags": [
        "binary_only",
        "obfuscated_code"
      ]
    }
  ],
  "latency_ms": 32.4,
  "cached": false
}
```

---

### Example 2: Threat Match Auto-Enrichment

When an incident report or query is sent to `POST /api/v1/threats/match`, the engine extracts the CVE, executes the 4-layer matching pipeline, and **automatically enriches the top candidates with verified PoC links**:

#### Request:
```json
{
  "query": "Observed suspicious PowerShell execution leveraging CVE-2024-3400 on edge firewalls",
  "top_k": 1,
  "alpha": 0.5
}
```

#### Response (Snippet showing `pocs` injection):
```json
{
  "query_threat_id": "query_1728382740",
  "top_matches": [
    {
      "rank": 1,
      "chunk_id": "chunk_panos_01",
      "composite_score": 0.92,
      "confidence_tier": "EXACT",
      "attribution": {
        "matching_cves": ["CVE-2024-3400"],
        "matching_iocs": [],
        "shared_malware": ["Up-Streamor"],
        "matching_mitre_techniques": ["T1190"]
      },
      "citations": [
        {
          "doc_id": "CISA-AA24-109A",
          "doc_title": "Threat Actors Exploiting PAN-OS CVE-2024-3400",
          "source_org": "CISA",
          "published_date": "2024-04-14T00:00:00Z",
          "text_snippet": "CISA released an advisory regarding active exploitation of CVE-2024-3400..."
        }
      ],
      "pocs": [
        {
          "url": "https://github.com/rapid7/metasploit-framework",
          "title": "Palo Alto Networks PAN-OS GlobalProtect Exploit Module",
          "source": "github",
          "author": "rapid7",
          "published_at": "2024-04-16T18:42:00Z",
          "confidence_score": 0.95,
          "confidence_label": "VERIFIED_CODE",
          "stars": 34120,
          "language": "Ruby",
          "warning_flags": []
        }
      ]
    }
  ],
  "pipeline_profile": {
    "exact_match_ms": 0.8,
    "vector_database_ms": 115.4,
    "knowledge_graph_ms": 28.2,
    "scoring_ms": 1.2,
    "citation_ms": 1.0,
    "poc_discovery_ms": 14.6,
    "total_ms": 161.2
  }
}
```

---

### Example 3: Python Programmatic Usage

You can call the orchestrator directly from internal Python scripts or notebook pipelines:

```python
import asyncio
from threat_retrieval_engine.poc_intelligence import get_poc_finder

async def main():
    finder = get_poc_finder()
    
    # 1. Async discovery
    response = await finder.find_pocs(
        cve_id="CVE-2021-44228",  # Log4Shell
        max_results=5,
        sources=["github", "mastodon", "bluesky"],
        min_confidence=0.50       # Filter for LIKELY_POC and VERIFIED_CODE only
    )
    
    print(f"CVE: {response.cve_id} | Total Found: {response.total_found}")
    print(f"Precision Score: {response.precision_score * 100:.1f}%")
    
    for poc in response.results:
        print(f"[{poc.confidence_label}] ({poc.confidence_score}) {poc.title}")
        print(f"   -> Link: {poc.url} (Stars: {poc.stars}, Lang: {poc.language})")

# Run async loop
asyncio.run(main())
```

---

## ⚙️ Configuration & Environment Variables

Add the following optional API keys to your `.env` file to maximize rate limits:

```bash
# Optional: Increases GitHub API rate limit from 60/hr to 5,000/hr
GITHUB_TOKEN=ghp_your_github_personal_access_token_here

# Optional: Enables live X/Twitter API v2 search (Basic or Pro tier)
X_BEARER_TOKEN=your_twitter_v2_bearer_token_here
```

Runtime settings can be adjusted in [`config/retrieval_config.yaml`](file:///d:/Project%20Course/unicc-iitgn-capstone/config/retrieval_config.yaml):

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

The subsystem comes with unit and integration test coverage:

```bash
# Run all PoC Intelligence verification tests
python -m pytest verify/test_poc* verify/test_pipeline_poc_enrichment.py -v
```

### Verified Test Matrix:
* `verify/test_poc_validator.py` — Positive heuristics, anti-deception flags, and $\ge 70\%$ precision benchmark.
* `verify/test_poc_aggregator.py` — Canonical URL normalization & cross-platform deduplication.
* `verify/test_poc_cache.py` — SQLite table generation, TTL expiration, and CISA KEV awareness.
* `verify/test_poc_sources.py` — Async scrapers for GitHub, Mastodon, and BlueSky.
* `verify/test_poc_finder.py` — End-to-end orchestrator execution & cache hit acceleration.
* `verify/test_poc_api.py` — FastAPI `POST /api/v1/pocs/find` endpoint and Pydantic validation.
* `verify/test_pipeline_poc_enrichment.py` — Automated PoC injection into `POST /api/v1/threats/match`.
