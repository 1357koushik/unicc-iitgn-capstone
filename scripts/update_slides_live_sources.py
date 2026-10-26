from pptx import Presentation
from pptx.dml.color import RGBColor

def update_presentation(pptx_path: str):
    prs = Presentation(pptx_path)
    slide10 = prs.slides[9]

    # Shape 13: Mastodon Badge -> Live Verified (Dark Green)
    shape13 = slide10.shapes[13]
    shape13.text = 'Live Verified'
    if len(shape13.text_frame.paragraphs[0].runs) > 0:
        shape13.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x16, 0x65, 0x34)
        shape13.text_frame.paragraphs[0].runs[0].font.bold = True

    # Shape 14: Mastodon Description
    shape14 = slide10.shapes[14]
    shape14.text = 'Adapter authenticated via Mastodon OAuth token on infosec.exchange. Live verified: searches federated security discussions and collects candidate PoC links.'
    if len(shape14.text_frame.paragraphs[0].runs) > 0:
        shape14.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x33, 0x41, 0x55)

    # Shape 18: Bluesky Badge -> Live Verified (Dark Green)
    shape18 = slide10.shapes[18]
    shape18.text = 'Live Verified'
    if len(shape18.text_frame.paragraphs[0].runs) > 0:
        shape18.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x16, 0x65, 0x34)
        shape18.text_frame.paragraphs[0].runs[0].font.bold = True

    # Shape 19: Bluesky Description
    shape19 = slide10.shapes[19]
    shape19.text = 'Adapter authenticated via AT Protocol app session (bsky.social). Live verified: finds public posts and collects author handles and candidate PoC links.'
    if len(shape19.text_frame.paragraphs[0].runs) > 0:
        shape19.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(0x33, 0x41, 0x55)

    # Shape 22: Live Captured Stream
    shape22 = slide10.shapes[22]
    lines = [
        'Example request: find PoC links for CVE-2024-3400 (up to 20 results)',
        '--------------------------------------------------------------------------------',
        'LIVE MULTI-SOURCE HARVEST STREAM (GitHub v3, Bluesky AT Protocol & Mastodon OAuth -- Verified Oct 25, 2026):',
        '  [GitHub repository]        https://github.com/ZephrFish/CVE-2024-3400-Canary (Python, author: ZephrFish; GitHub API)',
        '  [Mastodon Live Post]       https://infosec.exchange/@saltmyhash/114039171548967342 (author: @saltmyhash@infosec.exchange)',
        '  [Bluesky Social Verified]  https://bsky.app/profile/ntkramer.bsky.social/post/3kq77s7hiky2j (author: @ntkramer.bsky.social)',
        '  [Cross-Source Corroborated] Matches discovered across infosec.exchange and bsky.app for author @ntkramer',
        '  Note: A repository being found does not prove its code was run or works. "VERIFIED_CODE" is a heuristic estimate, not sandbox execution proof.',
        '  Live sources: GitHub, Bluesky, and Mastodon all live active. X/Twitter disabled to prevent paid tier charges.',
        '--------------------------------------------------------------------------------',
        'TEST EXAMPLES - SIMULATED DATA, NOT LIVE RESULTS (Unit Test Fixtures):',
        '  [Mock example] eternalblue repository - used to test code-verification logic.',
        '  [Mock example] fake cve_dropper repository - used to test detection of suspicious links.',
        '  [Mock example] simulated writeup - used to test cross-source corroboration.'
    ]
    shape22.text = '\n'.join(lines)

    prs.save(pptx_path)
    print(f'Successfully updated {pptx_path}!')

if __name__ == '__main__':
    update_presentation(r'D:\Project Course\unicc_presentation_v4.pptx')
