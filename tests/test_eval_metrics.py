"""B4 metric definitions on hand-built rankings. Every expected value is derived by hand in the comments.

Notation: gain(g) = 2^g - 1 (grade 2 -> 3, grade 1 -> 1); discount at rank r = 1 / log2(r + 1):
r=1 -> 1, r=2 -> 0.630930, r=3 -> 0.5, r=4 -> 0.430677, r=5 -> 0.386853.
"""
from __future__ import annotations

import math

import pytest

from benchmarks_v2.eval.metrics import Settings, evaluate_query, query_judgements, ranking_metrics
from benchmarks_v2.eval.schema import Query, Ranked, RunRecord, build_equivalence, Equivalence
from benchmarks_v2.eval.scoring import summarize

D2, D3, D4, D5 = 1 / math.log2(3), 0.5, 1 / math.log2(5), 1 / math.log2(6)
NOEQ = Equivalence()


def Q(qid="T0-1", answerable=None):
    sl = qid.split("-")[0]
    return Query(qid, sl, "dev", "t", (sl != "T7") if answerable is None else answerable, False, {"name": "generated"}, {})


def RR(qid, docs, tiers=None, probs=None, abstained=False, error=None, scores=None, latency=10.0):
    ranked = tuple(Ranked(d, scores[i] if scores else float(10 - i), tiers[i] if tiers else None,
                          probs[i] if probs else None) for i, d in enumerate(docs))
    return RunRecord(qid, "sys", ranked, abstained, latency, error)


def metrics_for(docs, grades, eq=NOEQ, min_grade=2):
    q = Q()
    qj = query_judgements(q, grades, eq)
    return ranking_metrics([eq.unit(d) for d in docs], qj, min_grade)


def test_binary_metrics_known_item():
    # Ranking A B C D E F; only C is relevant (grade 2); A, B, D-F judged 0.
    grades = {"CVE-2020-0003": 2, **{f"CVE-2020-000{i}": 0 for i in (1, 2, 4, 5, 6)}}
    docs = [f"CVE-2020-000{i}" for i in range(1, 7)]
    m, sc, unj, _ = metrics_for(docs, grades)
    assert m["success@1"] == 0.0
    assert m["success@5"] == 1.0            # rank 3 <= 5
    assert m["mrr@10"] == pytest.approx(1 / 3)
    # nDCG: DCG = 3 * D3 = 1.5; IDCG = 3 * 1 = 3 -> 0.5
    assert m["ndcg@10"] == pytest.approx(0.5)
    assert m["recall@10"] == 1.0 and m["recall@50"] == 1.0
    assert m["set_recall@10"] is None       # only one relevant unit
    assert unj == 0 and sc["success@1"] == 0.0


def test_graded_ndcg():
    # Ranking: X(1), Y(0), Z(2), W(1).  Judged: X=1, Y=0, Z=2, W=1, V=2 (V not retrieved).
    grades = {"CVE-2021-0001": 1, "CVE-2021-0002": 0, "CVE-2021-0003": 2, "CVE-2021-0004": 1, "CVE-2021-0005": 2}
    docs = ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004"]
    m, _, _, _ = metrics_for(docs, grades)
    # DCG = 1*1 + 0 + 3*0.5 + 1*D4 = 1 + 1.5 + 0.430677 = 2.930677
    # Ideal from all judged relevant: grades [2, 2, 1, 1] -> 3 + 3*D2 + 1*0.5 + 1*D4
    #   = 3 + 1.892789 + 0.5 + 0.430677 = 5.823466  -> nDCG = 2.930677 / 5.823466 = 0.503253
    dcg = 1 + 3 * D3 + D4
    idcg = 3 + 3 * D2 + D3 + D4
    assert m["ndcg@10"] == pytest.approx(dcg / idcg)
    assert m["ndcg@10"] == pytest.approx(0.503253, abs=1e-6)
    # Binary metrics use grade >= 2: first grade-2 document is Z at rank 3.
    assert m["success@1"] == 0.0 and m["mrr@10"] == pytest.approx(1 / 3)
    # Relevant units (grade 2): Z, V -> recall@10 = 1/2; set recall = 1 / min(2, 10) = 0.5
    assert m["recall@10"] == 0.5 and m["set_recall@10"] == 0.5
    # With min_grade = 1 the first relevant document is X at rank 1.
    m1, _, _, _ = metrics_for(docs, grades, min_grade=1)
    assert m1["success@1"] == 1.0 and m1["recall@10"] == pytest.approx(3 / 4)


def test_equivalence_collapse_hit_once_and_ideal_collapsed():
    # S = {A1, A2} describe the same flaw; B is a different relevant CVE. All judged grade 2.
    eq = build_equivalence([("S", ["CVE-2014-0160", "CVE-2014-0346"])])
    grades = {"CVE-2014-0160": 2, "CVE-2014-0346": 2, "CVE-2017-0144": 2}
    # Ranking [A2, B]: units [S, B] -> DCG = 3 + 3*D2 = 4.892789.
    # Ideal over collapsed units {S: 2, B: 2} = same 4.892789 -> nDCG 1.0.
    # (Without collapsing, the ideal would hold three grade-2 documents: 3 + 3*D2 + 3*0.5 = 6.392789 -> 0.765.)
    m, _, _, _ = metrics_for(["CVE-2014-0346", "CVE-2017-0144"], grades, eq)
    assert m["ndcg@10"] == pytest.approx(1.0)
    assert m["recall@10"] == 1.0          # 2 of 2 units, not 2 of 3 documents
    assert m["set_recall@10"] == 1.0
    # Ranking [A1, A2, B]: the second member occupies rank 2 with no gain and is not a new hit.
    # DCG = 3 + 0 + 3*0.5 = 4.5 -> nDCG = 4.5 / 4.892789 = 0.919721
    m, _, _, _ = metrics_for(["CVE-2014-0160", "CVE-2014-0346", "CVE-2017-0144"], grades, eq)
    assert m["ndcg@10"] == pytest.approx(4.5 / (3 + 3 * D2))
    assert m["success@1"] == 1.0 and m["mrr@10"] == 1.0


def test_equivalence_judgement_of_one_member_covers_the_set():
    # Only CVE-2014-0160 is judged; retrieving its unjudged duplicate CVE-2014-0346 is a hit, not unjudged.
    eq = build_equivalence([("S", ["CVE-2014-0160", "CVE-2014-0346"])])
    m, _, unj, _ = metrics_for(["CVE-2014-0346"], {"CVE-2014-0160": 2}, eq)
    assert m["success@1"] == 1.0 and unj == 0


def test_overlapping_equivalence_sets_are_merged():
    eq = build_equivalence([("a", ["CVE-2000-0001", "CVE-2000-0002"]), ("b", ["CVE-2000-0002", "CVE-2000-0003"])])
    assert eq.unit("CVE-2000-0001") == eq.unit("CVE-2000-0003") == "eq:a"
    assert eq.merged_sets == [["a", "b"]]


def test_unjudged_documents_are_counted_not_assumed_irrelevant():
    # Ranking [U, R, N]; U unjudged, R grade 2, N grade 0.
    grades = {"CVE-2022-0002": 2, "CVE-2022-0003": 0}
    m, sc, unj, ranks = metrics_for(["CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003"], grades)
    assert unj == 1 and ranks == [1]
    # value: U gives no gain -> S@1 0, MRR 1/2, nDCG = 3*D2 / 3 = 0.630930
    assert m["success@1"] == 0.0 and m["mrr@10"] == 0.5
    assert m["ndcg@10"] == pytest.approx(D2)
    # scenario "unjudged relevant": U has grade 2 -> S@1 1, MRR 1; gains [3, 3, 0]; ideal [2, 2] -> nDCG 1.0
    assert sc["success@1"] == 1.0 and sc["mrr@10"] == 1.0 and sc["ndcg@10"] == pytest.approx(1.0)
    # recall is relative to the judged relevant set: 1/1
    assert m["recall@10"] == 1.0


def test_ties_keep_the_order_of_the_run_file():
    # Both documents have score 5.0; the relevant one is second in the list and must stay at rank 2.
    q = Q("T3-1")
    qj = query_judgements(q, {"CVE-2020-0001": 0, "CVE-2020-0002": 2}, NOEQ)
    r = evaluate_query(q, RR("T3-1", ["CVE-2020-0001", "CVE-2020-0002"], scores=[5.0, 5.0]), qj, NOEQ, Settings())
    assert r.metrics["success@1"] == 0.0 and r.metrics["mrr@10"] == 0.5


def test_recall_at_depth():
    # 60 results; relevant at ranks 5, 40 and 70 (beyond the list); 3 relevant units in total.
    docs = [f"CVE-2023-{1000 + i}" for i in range(60)]
    grades = {docs[4]: 2, docs[39]: 2, "CVE-2023-9999": 2}
    m, _, _, _ = metrics_for(docs, grades)
    assert m["recall@10"] == pytest.approx(1 / 3)
    assert m["recall@50"] == pytest.approx(2 / 3)
    assert m["recall@100"] == pytest.approx(2 / 3)
    # set recall@10 = 1 relevant in top 10 / min(3, 10)
    assert m["set_recall@10"] == pytest.approx(1 / 3)


def test_error_and_abstention_count_as_misses():
    q = Q("T1-1")
    qj = query_judgements(q, {"CVE-2021-44228": 2}, NOEQ)
    s = Settings()
    err = evaluate_query(q, RR("T1-1", [], error="http_504: deadline"), qj, NOEQ, s)
    assert err.metrics["success@1"] == 0.0 and err.metrics["ndcg@10"] == 0.0 and err.error
    # Abstained but the right document is returned: with abstain_is_miss it scores 0.
    ab = evaluate_query(q, RR("T1-1", ["CVE-2021-44228"], abstained=True), qj, NOEQ, s)
    assert ab.metrics["success@1"] == 0.0 and ab.abstained


def test_false_accept_definition():
    s = Settings()
    q = Q("T7-1")
    qj = query_judgements(q, {}, NOEQ)
    cases = [
        (RR("T7-1", ["CVE-2000-0001"], tiers=["PARTIAL"]), 1),            # not abstained, top PARTIAL
        (RR("T7-1", ["CVE-2000-0001"], tiers=["STRONG"]), 1),
        (RR("T7-1", ["CVE-2000-0001"], tiers=["EXACT"]), 1),
        (RR("T7-1", ["CVE-2000-0001"], tiers=["WEAK"]), 0),               # below PARTIAL
        (RR("T7-1", ["CVE-2000-0001", "CVE-2000-0002"], tiers=["WEAK", "STRONG"]), 0),  # only the top counts
        (RR("T7-1", ["CVE-2000-0001"], tiers=["STRONG"], abstained=True), 0),  # abstained
        (RR("T7-1", []), 0),                                                # nothing returned
        (RR("T7-1", [], error="http_504: x"), 0),
        (RR("T7-1", ["CVE-2000-0001"]), 0),                                 # no tier
    ]
    for rec, want in cases:
        r = evaluate_query(q, rec, qj, NOEQ, s)
        assert r.false_accept == want, rec
        assert all(v is None for v in r.metrics.values())  # no ranking metrics for unanswerable queries


def test_population_abstention_rates_and_risk_coverage_by_hand():
    s = Settings(bootstrap=0)
    eq = NOEQ
    rows = []

    def add(q, rec, grades):
        rows.append(evaluate_query(q, rec, query_judgements(q, grades, eq), eq, s))

    # q1: top prob 0.9, correct.  q2: top prob 0.9 (tie), wrong.  q3: top prob 0.5, correct.
    # q4: abstained (answerable).  q5: unanswerable, top PARTIAL 0.8, not abstained (false accept, wrong).
    # q6: unanswerable, abstained.
    add(Q("T0-1"), RR("T0-1", ["CVE-2000-0001"], tiers=["STRONG"], probs=[0.9]), {"CVE-2000-0001": 2})
    add(Q("T0-2"), RR("T0-2", ["CVE-2000-0009"], tiers=["STRONG"], probs=[0.9]), {"CVE-2000-0002": 2, "CVE-2000-0009": 0})
    add(Q("T0-3"), RR("T0-3", ["CVE-2000-0003"], tiers=["WEAK"], probs=[0.5]), {"CVE-2000-0003": 2})
    add(Q("T0-4"), RR("T0-4", ["CVE-2000-0004"], tiers=["WEAK"], probs=[0.4], abstained=True), {"CVE-2000-0004": 2})
    add(Q("T7-1"), RR("T7-1", ["CVE-2000-0005"], tiers=["PARTIAL"], probs=[0.8]), {})
    add(Q("T7-2"), RR("T7-2", ["CVE-2000-0006"], tiers=["STRONG"], probs=[0.95], abstained=True), {})
    out = summarize(rows, s, "t")
    a = out["abstention"]
    assert a["false_accept_rate"]["value"] == 0.5 and a["false_accept_rate"]["false_accepts"] == 1
    assert a["abstention_rate_answerable"]["value"] == 0.25
    # Risk-coverage, N = 6. Confidence key = (tier rank, probability), highest first:
    #   q1 and q2 (STRONG, 0.9) tie -> accepted together: coverage 2/6, risk 1/2
    #   q5 (PARTIAL, 0.8): coverage 3/6, risk 2/3
    #   q3 (WEAK, 0.5):    coverage 4/6, risk 2/4
    #   q4, q6 abstained: never accepted -> max coverage 4/6.
    # AURC = (2/6)(1/2) + (1/6)(2/3) + (1/6)(1/2) = 0.166667 + 0.111111 + 0.083333 = 0.361111
    rc = a["risk_coverage"]
    assert rc["max_coverage"] == pytest.approx(4 / 6)
    assert rc["aurc"] == pytest.approx(2 / 6 * 1 / 2 + 1 / 6 * 2 / 3 + 1 / 6 * 1 / 2)
    assert [p[0] for p in rc["points"]] == pytest.approx([2 / 6, 3 / 6, 4 / 6])
    assert [p[1] for p in rc["points"]] == pytest.approx([1 / 2, 2 / 3, 2 / 4])


def test_unjudged_top1_is_excluded_from_risk_coverage():
    s = Settings(bootstrap=0)
    q = Q("T0-1")
    r = evaluate_query(q, RR("T0-1", ["CVE-2000-0007"], probs=[0.9]), query_judgements(q, {"CVE-2000-0001": 2}, NOEQ),
                       NOEQ, s)
    assert r.rc_excluded and r.rc_key is None and r.calib_unjudged == 1 and r.calib == []


def test_calibration_pairs_and_tier_precision_by_hand():
    s = Settings(bootstrap=0, ece_bins=2)
    q1, q2 = Q("T0-1"), Q("T7-1")
    rows = [
        # q1: A relevant (0.9 STRONG), B not (0.6 PARTIAL), C unjudged (excluded)
        evaluate_query(q1, RR("T0-1", ["CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"],
                              tiers=["STRONG", "PARTIAL", "WEAK"], probs=[0.9, 0.6, 0.2]),
                       query_judgements(q1, {"CVE-2000-0001": 2, "CVE-2000-0002": 0}, NOEQ), NOEQ, s),
        # q2 unanswerable: every result is a negative
        evaluate_query(q2, RR("T7-1", ["CVE-2000-0004"], tiers=["STRONG"], probs=[0.8]),
                       query_judgements(q2, {}, NOEQ), NOEQ, s),
    ]
    out = summarize(rows, s, "t")
    c = out["calibration"]
    assert c["n_pairs"] == 3 and c["unjudged_excluded"] == 1
    # Brier over pairs (0.9,1) (0.6,0) (0.8,0): (0.01 + 0.36 + 0.64) / 3 = 0.336667
    assert c["brier"]["value"] == pytest.approx(1.01 / 3)
    # STRONG: 2 pairs, 1 relevant -> 0.5; PARTIAL: 1 pair, 0 relevant
    assert c["tiers"]["STRONG"]["precision"] == 0.5 and c["tiers"]["STRONG"]["n"] == 2
    assert c["tiers"]["PARTIAL"]["precision"] == 0.0
    # ECE, 2 equal-mass bins over sorted p [0.6, 0.8, 0.9]: boundary after ceil(3/2) = 2nd -> {0.6, 0.8}, {0.9}
    #   bin 1: mean p 0.7, observed 0 -> 0.7 * 2/3;  bin 2: |0.9 - 1| = 0.1 * 1/3  -> ECE = 0.5
    assert c["ece"]["value"] == pytest.approx(0.7 * 2 / 3 + 0.1 / 3)
    assert c["ece"]["bins_effective"] == 2
