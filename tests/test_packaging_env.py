"""Environment overrides added for packaging (A2): TRE_DATA_DIR, TRE_CONFIG_PATH, TRE_NUM_THREADS."""

from __future__ import annotations

from pathlib import Path

from threat_retrieval_engine import config as cfgmod
from threat_retrieval_engine import runtime


def test_default_paths_anchor_to_repo_root(monkeypatch):
    monkeypatch.delenv("TRE_DATA_DIR", raising=False)
    got = cfgmod._resolve_path("./data/sqlite/corpus_store.db")
    assert got == (cfgmod.REPO_ROOT / "data" / "sqlite" / "corpus_store.db").resolve()


def test_data_dir_override(monkeypatch, tmp_path):
    monkeypatch.setenv("TRE_DATA_DIR", str(tmp_path))
    assert cfgmod._resolve_path("./data/sqlite/x.db") == (tmp_path / "sqlite" / "x.db").resolve()
    assert cfgmod._resolve_path("other/y") == (tmp_path / "other" / "y").resolve()
    absolute = Path(tmp_path / "abs.db").resolve()
    assert cfgmod._resolve_path(absolute) == absolute


def test_config_path_override(monkeypatch, tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("rrf_k: 77\n", encoding="utf-8")
    monkeypatch.setenv("TRE_CONFIG_PATH", str(f))
    monkeypatch.setattr(cfgmod, "_CONFIG_CACHE", None)
    loaded = cfgmod.load_config()
    assert loaded.rrf_k == 77
    assert loaded.config_path == f.resolve()


def test_thread_env(monkeypatch):
    monkeypatch.delenv("TRE_NUM_THREADS", raising=False)
    assert runtime.get_num_threads() == 16
    monkeypatch.setenv("TRE_NUM_THREADS", "5")
    assert runtime.get_num_threads() == 5
    for var in runtime.THREAD_ENV_VARS:
        monkeypatch.setenv(var, "1")  # restored on teardown
    monkeypatch.setitem(__import__("sys").modules, "torch", None)  # do not touch real torch
    assert runtime.apply_thread_env() == 5
    import os
    assert os.environ["OMP_NUM_THREADS"] == "5"
    monkeypatch.setenv("TRE_NUM_THREADS", "bogus")
    assert runtime.get_num_threads() == 16
