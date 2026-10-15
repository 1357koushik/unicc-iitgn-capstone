import asyncio
import os
import sys

# Ensure correct path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from llm import investigate_threat

def main():
    obs = "At 02:00 AM, our SOC detected suspicious activity on our edge firewall. An unauthenticated external actor sent a series of malformed HTTP requests containing directory traversal payloads aimed at our Citrix Application Delivery Controller. Shortly after, we observed abnormal child processes spawned by the web server process, indicating potential remote code execution. No specific CVE was identified by the IDS"

    print("--- TEST 1: ALL Datasets (allowed_sources=None) ---")
    res1 = investigate_threat(
        observation=obs,
        backend="gemini",
        team2_api_url="http://127.0.0.1:8000"
    )
    print("Matches found:", len(res1.get("top_matches", [])))
    if len(res1.get("top_matches", [])) > 0:
        print("Top match chunk:", res1["top_matches"][0].chunk_id)

    print("\n--- TEST 2: Only INTERNAL dataset (allowed_sources=['INTERNAL']) ---")
    res2 = investigate_threat(
        observation=obs,
        backend="gemini",
        team2_api_url="http://127.0.0.1:8000",
        allowed_sources=["INTERNAL"]
    )
    print("Matches found:", len(res2.get("top_matches", [])))

    print("\n--- TEST 3: Only NVD dataset (allowed_sources=['NVD']) ---")
    res3 = investigate_threat(
        observation=obs,
        backend="gemini",
        team2_api_url="http://127.0.0.1:8000",
        allowed_sources=["NVD"]
    )
    print("Matches found:", len(res3.get("top_matches", [])))

if __name__ == "__main__":
    main()
