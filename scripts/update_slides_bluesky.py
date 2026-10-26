from pptx import Presentation
from pptx.dml.color import RGBColor

prs = Presentation(r'D:\Project Course\unicc_presentation_v4.pptx')
slide10 = prs.slides[9]

# 1. Update Shape 19: Badge text and color
shape19 = slide10.shapes[19]
shape19.text = 'Live Verified'
shape19.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x16, 0x65, 0x34)
shape19.text_frame.paragraphs[0].runs[0].font.bold = True

# 2. Update Shape 20: Description text
shape20 = slide10.shapes[20]
shape20.text = 'Adapter authenticated via AT Protocol app session (bsky.social createSession). Live verified: extracts post telemetry, profile handles, and candidate PoC URLs.'
shape20.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x33, 0x41, 0x55)

# 3. Update Shape 23: Bottom live harvest capture block
shape23 = slide10.shapes[23]
lines = [
    'POST /api/v1/pocs/find  ->  {"cve_id": "CVE-2017-0144", "max_results": 20}',
    '------------------------------------------------------------------------------------------------------------------------',
    'LIVE CAPTURED HARVEST (GitHub REST API v3 & Bluesky AT Protocol -- Verified Oct 24, 2026):',
    '  [Repository Verified]      https://github.com/worawit/MS17-010 (2261 stars, Python, is_fork: false; GitHub API Oct 2026)',
    '  [Bluesky Social Verified]  https://bsky.app/profile/nihonmatsu.bsky.social/post/... (@nihonmatsu.bsky.social; AT Protocol Oct 2026)',
    '  [Heuristic False Positive] https://github.com/rxerium/CISA-KEV (5 stars, Python; Nuclei-KEV tracker, not exploit PoC)',
    '  * Distinction: "Repository Verified" confirms repo existence; "VERIFIED_CODE" is a heuristic score, not sandbox execution proof.',
    '  * Live Scope: Harvest covers GitHub (60 req/hr) and Bluesky (authenticated session). X disabled for cost protection, Mastodon verification pending.',
    '------------------------------------------------------------------------------------------------------------------------',
    'SYNTHETIC TEST FIXTURES -- NOT LIVE RESULTS (Unit Test Fixtures for Anti-Deception & De-Duplication):',
    '  [Mock Fixture] https://github.com/jamesbcook/eternalblue (Stars: 847, Python, fixture: test_verified_code)',
    '  [Mock Fixture] https://github.com/fake_attacker/cve_dropper (Stars: 0, Batch, fixture: malicious_lure_trap)',
    '  [Mock Fixture] https://infosec.exchange/@sec_mock/112... (Simulated writeup, fixture: cross_source_corroboration)'
]
shape23.text = '\n'.join(lines)

prs.save(r'D:\Project Course\unicc_presentation_v4_updated.pptx')
print('Saved to unicc_presentation_v4_updated.pptx!')
