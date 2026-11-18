"""PoC credentials are read from an env file: only the PoC keys, never replacing a set variable."""
from threat_retrieval_engine.runtime import POC_CREDENTIAL_KEYS, load_poc_credentials


def test_only_poc_keys_are_loaded(tmp_path, monkeypatch):
    for k in POC_CREDENTIAL_KEYS + ("JWT_SECRET",):
        monkeypatch.setenv(k, "placeholder")     # records the original state, restored after the test
        monkeypatch.delenv(k)
    f = tmp_path / ".env"
    f.write_text('# comment\nBLUESKY_HANDLE=demo.bsky.social\nexport GITHUB_TOKEN="tok"\nJWT_SECRET=s\n'
                 "MASTODON_ACCESS_TOKEN=\n", encoding="utf-8")
    import os
    got = load_poc_credentials([f])
    assert sorted(got) == ["BLUESKY_HANDLE", "GITHUB_TOKEN"]
    assert os.environ["BLUESKY_HANDLE"] == "demo.bsky.social" and os.environ["GITHUB_TOKEN"] == "tok"
    assert "JWT_SECRET" not in os.environ and not os.environ.get("MASTODON_ACCESS_TOKEN")


def test_existing_variable_is_not_replaced(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUESKY_HANDLE", "already.set")
    f = tmp_path / ".env"
    f.write_text("BLUESKY_HANDLE=other\n", encoding="utf-8")
    import os
    assert load_poc_credentials([f]) == []
    assert os.environ["BLUESKY_HANDLE"] == "already.set"


def test_missing_file_is_ignored(tmp_path):
    assert load_poc_credentials([tmp_path / "absent.env"]) == []
