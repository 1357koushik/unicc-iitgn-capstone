"""C9 through the API layer: `stix_relationships` come only from the ATT&CK build and every entry names a
stored edge by ATT&CK IDs; health reports the component with its build ID; entity parsing uses the
gazetteer; without a build there are no entities and no relationships, and the component is degraded."""
import pytest

from threat_retrieval_engine.attack import AttackGraph, AttackStore, runtime
from threat_retrieval_engine.attack import build as AB
from threat_retrieval_engine.attack.check_c9 import (PACKAGE_ROOT, check_relationship_strings, probe_api,
                                                      probe_queries, scan_hardcoded)
from threat_retrieval_engine.store import build as SB

from attack_fixtures import low_df_policy, make_attack_sources
from store_fixtures import make_feeds, make_sources


@pytest.fixture(scope="module")
def graph(tmp_path_factory):
    root = tmp_path_factory.mktemp("c9api")
    store = SB.build(make_feeds(root), make_sources(root), root / "store", workers=1, build_id="c1-api",
                     log=lambda m: None)
    out = AB.build(make_attack_sources(root), store, root / "attack", build_id="c9-api", log=lambda m: None,
                   policy=low_df_policy())
    g = AttackGraph(AttackStore.open(out))
    yield g
    runtime.reset()
    g.store.close()


@pytest.fixture()
def installed(graph):
    runtime.set_attack_graph(graph)
    yield graph
    runtime.set_attack_graph(None, error="test teardown")
    runtime.reset()


def test_api_relationships_traceable_and_health(installed):
    qs = ["APT29 deployed Cobalt Strike and used T1059.001", "incident attributed to NOBELIUM", "T1086 seen",
          "Dark Halo and OldBeacon"]
    res = probe_api(installed, qs)
    n, bad = check_relationship_strings(installed.store, res["responses"])
    assert n > 0 and bad == []
    strings = {s for _, _, b in res["responses"] for m in b["top_matches"] for s in m["stix_relationships"]}
    assert "[QUERY_CONTEXT] G0016 (APT29) -[uses]-> S0154 (Cobalt Strike)" in strings
    assert "[QUERY_CONTEXT] S0154 (Cobalt Strike) -[uses]-> T1059.001 " \
           "(Command and Scripting Interpreter: PowerShell)" in strings
    # the probe corpus chunk names APT28, whose only edge was redirected from the revoked T1086
    assert "[DOCUMENT] G0007 (APT28) -[uses]-> T1059.001 (Command and Scripting Interpreter: PowerShell)" in strings
    assert not any("revoked-by" in s for s in strings)
    h = res["health"]
    assert h["components"]["knowledge_graph"] == "available"
    assert h["builds"]["attack"]["build_id"] == "c9-api" and h["builds"]["attack"]["attack_version"] == "20.1"
    assert "attack_graph" not in h["degraded_components"]


def test_probe_queries_come_from_the_build(installed):
    qs = probe_queries(installed.store)
    assert qs[0].startswith("APT29 deployed Cobalt Strike and used T")
    assert any("T1086" in q for q in qs)


def test_relationship_string_checker_rejects_untraceable(installed):
    fake = [("q", 200, {"top_matches": [{"stix_relationships": [
        "[QUERY_CONTEXT] APT29 -[uses]-> T1021.002",                                    # v1 stub form, no IDs
        "[DOCUMENT] G0016 (APT29) -[uses]-> T1021.002 (Remote Services: SMB/Windows Admin Shares)",  # no such edge
        "[DOCUMENT] G0016 (Cozy) -[uses]-> S0154 (Cobalt Strike)"]}]})]                 # wrong name
    n, bad = check_relationship_strings(installed.store, fake)
    assert n == 3 and len(bad) == 3


def test_entity_parsing_uses_the_gazetteer(installed):
    from threat_retrieval_engine.api.confidence import parse_query_profile
    from threat_retrieval_engine.api.helpers import extract_attribution, parse_query_entities
    e = parse_query_entities("Cozy Bear used net.exe and CobaltStrike; see T1086")
    assert e.threat_actors == ["APT29"] and e.malware == ["CozyCar", "Net", "Cobalt Strike"]
    assert e.mitre_techniques == ["T1059.001", "T1086"]
    assert parse_query_entities("net income at the bank").malware == []
    p = parse_query_profile("APT 29 with Cobalt Strike")
    assert p.threat_actors == ("apt29",) and p.malware == ("cobalt strike",)
    # chunk software adds the techniques it uses in the graph (replaces the old tool -> technique table)
    attr = extract_attribution(parse_query_entities("cobalt strike T1021.002"), {"entities": {}},
                               "The operators staged Cobalt Strike beacons.")
    assert attr["shared_malware"] == ["Cobalt Strike"] and attr["matching_mitre_techniques"] == ["T1021.002"]


def test_feature_extractor_uses_graph(installed):
    from threat_retrieval_engine.api.confidence import parse_query_profile
    from threat_retrieval_engine.api.feature_extractor import extract_features
    f = extract_features(parse_query_profile("T1059.001 activity"),
                         {"text": "A beacon from CobaltStrike.", "metadata": {"entities": {}}})
    assert f["has_ttp"] == 1.0 and f["ttp_coverage"] == 1.0
    f2 = extract_features(parse_query_profile("Sofacy"), {"text": "x", "metadata": {
        "entities": {"threat_actors": ["APT28"]}}})
    assert f2["ttp_coverage"] == 1.0                                   # alias and name resolve to one object


def test_unavailable_component_is_reported_and_yields_nothing(tmp_path, monkeypatch):
    from threat_retrieval_engine.api.helpers import parse_query_entities
    from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine
    from unittest.mock import MagicMock
    runtime.reset()
    monkeypatch.setenv("TRE_ATTACK_DIR", str(tmp_path / "nowhere"))
    try:
        assert runtime.status()["status"] == "unavailable" and "no C9 ATT&CK build" in runtime.status()["reason"]
        assert parse_query_entities("APT29 used Cobalt Strike").threat_actors == []
        eng = ThreatRetrieverEngine(qdrant_client=MagicMock(), sqlite_conn=MagicMock(), hybrid_searcher=MagicMock(),
                                    reranker=MagicMock(), confidence_model=MagicMock())
        eng.initialize()
        assert eng.attack_graph is None and "attack_graph" in eng.degraded_components
        assert eng.attack_graph_status["status"] == "unavailable"
    finally:
        runtime.reset()


def test_no_hardcoded_lists_in_package(installed):
    assert scan_hardcoded(installed.store, PACKAGE_ROOT) == []


def test_hardcoded_scan_finds_a_planted_list(installed, tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text('"""Docstring naming APT29 is fine."""\nACTORS = ["apt29", "cobalt strike"]\n'
                              'X = "starter_stub"\n', encoding="utf-8")
    hits = scan_hardcoded(installed.store, pkg)
    assert any("'apt29'" in h for h in hits) and any("'cobalt strike'" in h for h in hits)
    assert any("starter_stub" in h for h in hits) and not any("Docstring" in h for h in hits)
