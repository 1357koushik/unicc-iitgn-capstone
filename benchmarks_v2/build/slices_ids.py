"""T1 (identifier) and T7 (unanswerable) slices: generated text."""
from __future__ import annotations

import ipaddress
import re

from .common import rng, seeded_sample
from .model import GENERATED, Item, qrel

# ----------------------------------------------------------------------------------------------- T1
T1_PLAN = [("canonical", 40), ("lower_case", 25), ("mixed_case", 15), ("in_sentence", 80), ("two_ids", 35),
           ("three_ids", 15), ("malformed", 90)]
T1_SENTENCES = [
    "Is a vendor fix out for {id}?",
    "what do we know about {id}",
    "{id} exploitation status",
    "Our scanner flagged {id} on three hosts, what is it?",
    "Need the severity and fix for {id}",
    "background on {id} for the incident ticket",
    "Has anyone seen {id} used against customers?",
    "summary of {id} for the change board",
    "Which products are affected by {id}?",
    "ticket mentions {id} - is it relevant to us?",
    "{id} remediation steps",
    "explain {id} in plain words",
]
T1_MULTI = ["{a} and {b}", "{a}, {b}", "compare {a} with {b}", "{a} / {b} status",
            "{a}, {b} and {c}", "{a} {b} {c}", "patches for {a}, {b}, {c}?"]
MALFORMED = ["spaces", "underscores", "en_dash", "no_first_hyphen", "parenthesised", "trailing_punctuation",
             "colon", "double_space"]


def _malform(cid: str, kind: str) -> str:
    _, y, n = cid.split("-")
    return {
        "spaces": f"CVE {y} {n}",
        "underscores": f"CVE_{y}_{n}",
        "en_dash": f"CVE–{y}–{n}",
        "no_first_hyphen": f"CVE{y}-{n}",
        "parenthesised": f"({cid})",
        "trailing_punctuation": f"{cid}.",
        "colon": f"CVE:{y}-{n}",
        "double_space": f"cve  {y}-{n}",
    }[kind]


def build_t1(u, gate, seed: int) -> tuple[list[Item], dict]:
    pool = sorted(c for c in u.nvd if u.nvd[c]["st"] != "Rejected" and u.nvd[c]["desc"])
    need = sum(n * (3 if k == "three_ids" else 2 if k == "two_ids" else 1) for k, n in T1_PLAN)
    picked = [c for c in seeded_sample(pool, need * 3, seed, "t1") if u.searchable(c)]
    items: list[Item] = []
    k = 0
    for kind, n in T1_PLAN:
        got = 0
        j = 0
        while got < n and k < len(picked) - 3:
            r = rng(seed, "t1", kind, j)
            j += 1
            if kind in ("two_ids", "three_ids"):
                m = 2 if kind == "two_ids" else 3
                ids = picked[k:k + m]
                k += m
                tmpl = [t for t in T1_MULTI if ("{c}" in t) == (m == 3)]
                text = r.choice(tmpl).format(a=ids[0], b=ids[1], c=ids[2] if m == 3 else "")
                meta = {"variant": kind}
            else:
                ids = [picked[k]]
                k += 1
                cid = ids[0]
                meta = {"variant": kind}
                if kind == "canonical":
                    text = cid
                elif kind == "lower_case":
                    text = cid.lower()
                elif kind == "mixed_case":
                    text = "Cve" + cid[3:]
                elif kind == "in_sentence":
                    text = r.choice(T1_SENTENCES).format(id=cid if r.random() < 0.7 else cid.lower())
                else:
                    sub = MALFORMED[got % len(MALFORMED)]
                    text = _malform(cid, sub)
                    meta["malformation"] = sub
            it = Item(slice="T1", text=text, qrels=[qrel(c, 2, "known_item") for c in ids],
                      source=dict(GENERATED), meta=meta, overlap_exempt=True)
            if gate.accept(it):
                items.append(it)
                got += 1
    return items, {"pool": len(pool), "generated": len(items)}


# ----------------------------------------------------------------------------------------------- T7
OFF_TOPIC = [
    "best way to cook basmati rice without it getting sticky", "how many cups are in a litre",
    "what time does the sun set in Reykjavik in June", "recommend a good fantasy novel for a long flight",
    "how do I remove a red wine stain from a carpet", "who won the 1998 football world cup",
    "easy vegetarian lasagne recipe for six people", "how to train a puppy to stop biting",
    "what is the capital of Mongolia", "how long should I boil an egg for a runny yolk",
    "tips for running my first half marathon", "difference between baking soda and baking powder",
    "how to repot an orchid", "what causes the northern lights", "best beaches near Lisbon",
    "how to tie a bowline knot", "convert 72 Fahrenheit to Celsius", "what is the plot of Hamlet",
    "how do solar panels generate electricity", "good stretches for lower back pain after sitting",
    "how to make sourdough starter from scratch", "what is the tallest mountain in Africa",
    "how many players are on a rugby union team", "suggest a weekend itinerary for Kyoto",
    "how to fix a squeaky door hinge", "what year did the Berlin Wall fall",
    "how to calculate compound interest on savings", "why is the sky blue",
    "what is a good houseplant for low light", "how to play the C major scale on piano",
    "how far is the moon from the earth", "what is photosynthesis in simple words",
    "how to get rid of fruit flies in the kitchen", "best time of year to visit Patagonia",
    "how do I unclog a bathroom sink", "what is the difference between weather and climate",
    "how to write a thank you note to a teacher", "rules of chess castling",
    "what vitamins are in spinach", "how to knit a scarf for beginners", "how do tides work",
    "recommend a board game for four adults", "how to change a flat bicycle tyre",
    "what language is spoken in Brazil", "how to make cold brew coffee at home",
    "what is the speed of sound in air", "how to prune a rose bush in autumn",
    "list of planets in order from the sun", "how to improve my handwriting",
    "what is the population of Canada", "quarterly sales forecast template for a bakery",
    "how to sort a list of dictionaries by a key in python", "what is a pivot table in a spreadsheet",
    "how do I centre a div with flexbox", "explain the Pythagorean theorem with an example",
    "how to merge two sorted arrays", "what is the derivative of sin x",
    "how to set up a monthly household budget", "what is a Roth IRA",
    "how to prepare for a job interview at a bank", "how to clean a cast iron pan",
    "what is the boiling point of water at high altitude", "how to grow tomatoes on a balcony",
    "what is the best way to learn Spanish quickly", "how many bones are in the human body",
    "how to draw a realistic eye", "who painted the Girl with a Pearl Earring",
    "how to fold a fitted sheet", "what is the gestation period of an elephant",
    "how to make a paper aeroplane that flies far", "what are the symptoms of dehydration",
    "how do noise cancelling headphones work", "plan a birthday party for a seven year old",
    "how to make hummus without tahini", "what is the meaning of the word serendipity",
    "how to iron a dress shirt", "what is the offside rule in football",
    "how to brew green tea properly", "how does a refrigerator keep food cold",
    "how to start a vegetable compost bin", "what is a haiku and how do I write one",
    "best exercises to strengthen knees", "how to read a nutrition label",
    "how to write a cover letter for a teaching job", "what is the history of the Olympic games",
    "how to make pancakes fluffy", "what is the largest desert in the world",
    "how to keep cut flowers fresh longer", "how do vaccines train the immune system",
    "how to calculate the area of a circle", "recommend a podcast about ancient history",
    "how to stop a dripping tap", "what is the difference between a crocodile and an alligator",
    "how to do a proper push up", "what is inflation and why does it happen",
    "how long does it take to fly from London to Sydney", "how to make a smoothie bowl",
    "what is the theory of relativity in simple terms", "how to choose a good watermelon",
    "how to keep basil alive indoors", "what is the difference between a lake and a pond",
    "best stretches before playing tennis", "how to make a budget travel plan for Vietnam",
    "what is the origin of the word quarantine", "how to paint a room without streaks",
    "who wrote Pride and Prejudice", "how to make gnocchi from potatoes", "how many teaspoons are in a tablespoon",
    "what is a leap year and why do we have them", "how to teach a child to ride a bike",
    "what is the best way to store fresh berries", "how do bees make honey", "how to write a limerick",
    "what is the circumference of the earth", "how to choose running shoes for flat feet",
]
SECURITY_ABSENT = [
    "average salary for a SOC analyst in Germany", "study plan for the CISSP exam in eight weeks",
    "how many CPE credits are needed to renew Security+", "difference between SOC 2 Type I and Type II reports",
    "template for an acceptable use policy for staff laptops", "how to budget for a security awareness programme",
    "what should a board-level cyber risk report contain", "dates of the next Black Hat conference",
    "who founded the first computer emergency response team", "how to write a job description for a CISO",
    "GDPR breach notification deadline to the supervisory authority", "what does HIPAA require for audit log retention",
    "cyber insurance premium factors for a mid-size retailer", "how to run a tabletop exercise for executives",
    "RACI chart for an incident response team", "how to structure a vulnerability disclosure programme page",
    "best books on the history of cryptography", "how to set up a security champions programme",
    "what is the role of a data protection officer", "interview questions for a junior penetration tester",
    "how to measure the maturity of a security operations centre", "ISO 27001 certification cost for a startup",
    "how many people should a security team have per 1000 employees", "what is the NIST CSF Govern function",
    "how to present security metrics to non-technical managers", "career path from help desk to security engineer",
    "what is the difference between a CISO and a CSO", "how to plan a security conference talk",
    "which universities offer a master's in cybersecurity online", "how to write a security newsletter for staff",
    "how to choose a managed security service provider contract length", "what is a security operations budget benchmark",
    "how long does a PCI DSS assessment usually take", "how to organise a capture the flag event for students",
    "examples of security awareness poster slogans", "what is the EU NIS2 directive scope for small companies",
    "how to negotiate a penetration test statement of work", "what is the purpose of a risk register",
    "how to calculate annualised loss expectancy", "what certifications does a cloud security architect need",
    "how to onboard a new analyst to a security team", "difference between ISO 27001 and ISO 27002",
    "how to write a business continuity plan for a small office", "how to run a security retrospective after a project",
    "what is the role of an internal audit function in IT governance", "who is responsible for third-party risk reviews",
    "how to report security KPIs every quarter", "what is the typical length of a SOC shift rotation",
    "how to request a security budget increase", "template for a security steering committee agenda",
]
FRAMEWORK_TMPL = ["What does {fw} {unit} {n} require?", "summary of {fw} {unit} {n}",
                  "how do we evidence {fw} {unit} {n} for the auditor", "{fw} {unit} {n} checklist"]
FRAMEWORKS = [("ISO 27001 Annex A", "control", ["5.1", "5.7", "5.23", "6.3", "7.4", "8.12", "8.16", "8.28"]),
              ("PCI DSS v4.0", "requirement", ["3.5.1", "6.4.3", "8.3.6", "10.2.1", "11.6.1", "12.10.1"]),
              ("SOC 2", "criterion", ["CC6.1", "CC7.2", "CC8.1", "CC9.2", "A1.2"]),
              ("GDPR", "article", ["25", "30", "32", "33", "35"]),
              ("NIST SP 800-53", "control", ["AC-2", "AU-6", "CM-7", "IR-4", "SC-7", "RA-5"])]
IOC_TMPL = ["{x}", "is {x} malicious?", "seen {x} in proxy logs, what is it", "{x} reputation",
            "threat intel on {x}", "block {x}?"]
NONEXIST_TMPL = ["{id}", "Is {id} exploited in the wild?", "is a fix available for {id}", "what is {id}",
                 "vendor bulletin covering {id}", "{id} affected versions"]
_WORDS = ["update", "secure", "cloud", "portal", "verify", "login", "cdn", "mail", "service", "account",
          "payment", "office", "sync", "data", "auth", "files", "support", "check", "online", "static"]
_TLDS = ["com", "net", "org", "info", "xyz", "top", "io", "online", "site"]


def _ipv4(r) -> str:
    while True:
        ip = ipaddress.IPv4Address(r.randrange(1 << 24, (224 << 24)))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def build_t7(u, kb, gate, seed: int, per_category: int = 100) -> tuple[list[Item], dict]:
    items: list[Item] = []
    stats = {"rejected_ioc_in_corpus": 0, "rejected_id_exists": 0}
    attack_text = " ".join((o.get("description") or "").lower() for o in kb.all_objects.values())

    def add(text: str, cat: str, **meta) -> None:
        items.append(Item(slice="T7", text=text, qrels=[], source=dict(GENERATED), answerable=False,
                          overlap_exempt=True, meta={"category": cat, **meta}))

    for t in OFF_TOPIC:
        add(t, "off_topic")
    for t in SECURITY_ABSENT:
        add(t, "security_absent_from_corpus")
    r = rng(seed, "t7", "framework")
    combos = [(fw, unit, n, tm) for fw, unit, ns in FRAMEWORKS for n in ns for tm in FRAMEWORK_TMPL]
    for fw, unit, n, tm in seeded_sample(combos, per_category + 40 - len(SECURITY_ABSENT), seed, "t7fw"):
        add(tm.format(fw=fw, unit=unit, n=n), "security_absent_from_corpus", template="framework_clause")
    # IOC-only
    r = rng(seed, "t7", "ioc")
    iocs: list[tuple[str, str]] = []
    while len(iocs) < per_category + 40:
        kind = ["md5", "sha1", "sha256", "ipv4", "domain", "url"][len(iocs) % 6]
        if kind in ("md5", "sha1", "sha256"):
            x = "%0*x" % ({"md5": 32, "sha1": 40, "sha256": 64}[kind],
                          r.getrandbits({"md5": 128, "sha1": 160, "sha256": 256}[kind]))
            val = x
        elif kind == "ipv4":
            val = _ipv4(r)
        else:
            d = f"{r.choice(_WORDS)}-{r.choice(_WORDS)}{r.randrange(10, 999)}.{r.choice(_TLDS)}"
            val = d if kind == "domain" else f"hxxp://{d.replace('.', '[.]')}/{r.choice(_WORDS)}/{r.randrange(100, 9999)}.php"
            if kind == "domain" and r.random() < 0.3:
                val = d.replace(".", "[.]")
        plain = val.replace("[.]", ".").replace("hxxp://", "").lower()
        host = plain.split("/")[0]
        if plain in u.corpus_iocs or host in u.corpus_iocs or host in attack_text or plain in attack_text:
            stats["rejected_ioc_in_corpus"] += 1
            continue
        iocs.append((kind, val))
    for j, (kind, val) in enumerate(iocs):
        add(rng(seed, "t7ioc", j).choice(IOC_TMPL).format(x=val), "ioc_only", ioc_type=kind)
    # Well-formed, non-existent CVE IDs
    maxnum: dict[int, int] = {}
    for c in u.nvd:
        _, y, n = c.split("-")
        maxnum[int(y)] = max(maxnum.get(int(y), 0), int(n))
    r = rng(seed, "t7", "nonexist")
    years = sorted(y for y in maxnum if 1999 <= y)
    made = []
    seen = set()
    while len(made) < per_category + 40:
        y = years[r.randrange(len(years))]
        hi = max(9999, maxnum[y])
        n = r.randrange(1000, hi + 1)
        cid = f"CVE-{y}-{n:04d}"
        if cid in seen:
            continue
        seen.add(cid)
        if u.exists(cid) or cid in u.mentioned_ids:
            stats["rejected_id_exists"] += 1
            continue
        made.append(cid)
    for j, cid in enumerate(made):
        add(rng(seed, "t7id", j).choice(NONEXIST_TMPL).format(id=cid), "nonexistent_cve_id", cve_id=cid,
            verified_absent=["nvd", "cve_list", "kev", "epss", "nvd_description_mentions"])
    cats = ("off_topic", "security_absent_from_corpus", "ioc_only", "nonexistent_cve_id")
    stats["candidates_by_category"] = {c: sum(1 for i in items if i.meta["category"] == c) for c in cats}
    kept: list[Item] = []
    for c in cats:
        got = 0
        for it in items:
            if it.meta["category"] == c and got < per_category and gate.accept(it):
                kept.append(it)
                got += 1
    stats["by_category"] = {c: sum(1 for i in kept if i.meta["category"] == c) for c in cats}
    return kept, stats
