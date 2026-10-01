import json
import urllib.request
import urllib.error

def fetch_team2(allowed_sources=None):
    url = "http://127.0.0.1:8000/match"
    payload = {
        "query": "CVE-2019-19781",
        "top_k": 5,
        "alpha": 0.5
    }
    if allowed_sources is not None:
        payload["allowed_sources"] = allowed_sources
    
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("top_matches", [])
    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    print("--- TEST 1: ALL Datasets (allowed_sources=None) ---")
    matches = fetch_team2(None)
    print("Matches found:", len(matches))
    if matches:
        print("Top Match Source:", matches[0].get("citations", [{}])[0].get("source_org"))

    print("\n--- TEST 2: Only INTERNAL dataset (allowed_sources=['INTERNAL']) ---")
    matches = fetch_team2(["INTERNAL"])
    print("Matches found:", len(matches))
    if matches:
        print("Top Match Source:", matches[0].get("citations", [{}])[0].get("source_org"))

    print("\n--- TEST 3: Only NVD dataset (allowed_sources=['NVD']) ---")
    matches = fetch_team2(["NVD"])
    print("Matches found:", len(matches))
    if matches:
        print("Top Match Source:", matches[0].get("citations", [{}])[0].get("source_org"))

if __name__ == "__main__":
    main()
