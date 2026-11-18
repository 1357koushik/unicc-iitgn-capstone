from pptx import Presentation
from pptx.util import Pt
from pptx.dml.color import RGBColor

def update_slide11(pptx_path: str):
    prs = Presentation(pptx_path)
    slide11 = prs.slides[10]

    # Shape 3 is the validated schema card
    shape3 = slide11.shapes[3]

    content = """VALIDATED MULTI-SOURCE OUTPUT (PoCResultSchema):
---------------------------------------------------
1. GITHUB REPOSITORY MATCH (Live Verified - Score: 0.95):
{
  "cve_id": "CVE-2024-3400",
  "url": "https://github.com/kevinmhorvath/exploit-availability-check",
  "source": "github",
  "author": "kevinmhorvath",
  "confidence_score": 0.95,
  "confidence_label": "HIGH_RELEVANCE_POC_CANDIDATE",
  "stars": 14,
  "language": "Python",
  "is_fork": false,
  "score_reasons": ["+0.35 exact CVE match", "+0.25 explicit PoC terminology", "+0.25 code evidence: Python", "+0.10 community stars (14)"]
}

2. MASTODON OSINT POST (Live Verified - Score: 0.85):
{
  "cve_id": "CVE-2024-3400",
  "url": "https://infosec.exchange/@saltmyhash/114039171548967342",
  "source": "mastodon",
  "author": "@saltmyhash@infosec.exchange",
  "confidence_score": 0.85,
  "confidence_label": "HIGH_RELEVANCE_POC_CANDIDATE",
  "score_reasons": ["+0.35 exact CVE match", "+0.25 explicit PoC terminology", "+0.25 security dump discussion"]
}

3. BLUESKY OSINT POST (Live Verified - Score: 0.60):
{
  "cve_id": "CVE-2024-3400",
  "url": "https://bsky.app/profile/ntkramer.bsky.social/post/3kq77s7hiky2j",
  "source": "bluesky",
  "author": "@ntkramer.bsky.social",
  "confidence_score": 0.60,
  "confidence_label": "POSSIBLE_POC",
  "score_reasons": ["+0.35 exact CVE match", "+0.25 explicit PoC terminology"]
}

* Anti-Deception & Cost Protection Scope:
  - Twitter/X API v2: Explicitly disabled (X_ENABLED=false) to prevent paid tier costs.
  - Multi-source corroboration automatically detected across Mastodon and Bluesky.
  - Heuristic score only; PoC discovery is decoupled from core retrieval (include_pocs=false)."""

    shape3.text = content

    # Format nicely with Consolas 8pt so it fits cleanly
    tf = shape3.text_frame
    for p in tf.paragraphs:
        p.font.name = "Consolas"
        p.font.size = Pt(8.5)
        p.font.color.rgb = RGBColor(0x33, 0x41, 0x55)

    prs.save(pptx_path)
    print("Slide 11 successfully updated with 3 individual verified live sources!")

if __name__ == "__main__":
    update_slide11(r"D:\Project Course\unicc_presentation_v4.pptx")
