"""
Setting the Gemini API key and model: from .env, from the dashboard (System Config),
and how a key Google rejects is reported. No request ever reaches Google: every call
to Google is replaced by a stand-in.

Run:  python -m pytest tests/test_gemini_settings.py -v
"""
import io
import json
import os
import urllib.error

os.environ["LOAD_DOTENV"] = "0"             # ignore your personal .env settings
os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest                                # noqa: E402
from fastapi.testclient import TestClient    # noqa: E402
from sqlalchemy import create_engine         # noqa: E402
from sqlalchemy.orm import sessionmaker      # noqa: E402
from sqlalchemy.pool import StaticPool       # noqa: E402

from backend import config, gemini_settings  # noqa: E402
from backend.api import main                 # noqa: E402
from backend.api.main import app, get_db     # noqa: E402
from backend.auth.passwords import get_password_hash   # noqa: E402
from backend.database import Base            # noqa: E402
from backend.models import AuditLog, SystemConfig, User   # noqa: E402
from llm.gateway.api import gemini_provider  # noqa: E402
from llm.gateway.api.gemini_provider import (  # noqa: E402
    DEFAULT_GEMINI_MODEL, GeminiProvider, check_gemini, classify_gemini_error,
    clean_api_key, clean_model_name,
)

GOOD_KEY = "AIzaSyTEST-good-key-0000000000000wxyz"
BAD_KEY = "AIzaSyTEST-bad-key-00000000000000bad1"
PASSWORD = "gemini-settings-test-password"


def google_error(code, message, status, reason=None) -> bytes:
    error = {"code": code, "message": message, "status": status}
    if reason:
        error["details"] = [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}]
    return json.dumps({"error": error}).encode()


def http_error(code, body: bytes):
    return urllib.error.HTTPError("https://example.invalid", code, "error", {}, io.BytesIO(body))


INVALID_KEY_BODY = google_error(400, "API key not valid. Please pass a valid API key.", "INVALID_ARGUMENT", "API_KEY_INVALID")


# ---------------------------------------------------------------- .env loading
@pytest.fixture
def env_file(tmp_path, monkeypatch):
    monkeypatch.setenv("LOAD_DOTENV", "1")
    monkeypatch.setattr(config, "_FROM_FILE", set())
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    path = tmp_path / ".env"
    yield path
    os.environ.pop("GEMINI_API_KEY", None)
    os.environ.pop("GEMINI_MODEL", None)


def test_empty_environment_variable_does_not_hide_env_file(env_file, monkeypatch):
    # Docker's "GEMINI_API_KEY=${GEMINI_API_KEY}" or a terminal can leave the variable EMPTY.
    monkeypatch.setenv("GEMINI_API_KEY", "")
    env_file.write_text(f"GEMINI_API_KEY={GOOD_KEY}\n")
    assert config.load_env_file(env_file)
    assert os.environ["GEMINI_API_KEY"] == GOOD_KEY


def test_real_environment_variable_still_wins(env_file, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "from-the-environment")
    env_file.write_text(f"GEMINI_API_KEY={GOOD_KEY}\n")
    config.load_env_file(env_file)
    assert config.current_setting("GEMINI_API_KEY", path=env_file) == "from-the-environment"


def test_key_added_to_env_file_while_running_is_used_without_restart(env_file):
    env_file.write_text("GEMINI_API_KEY=\n")
    config.load_env_file(env_file)
    assert config.current_setting("GEMINI_API_KEY", path=env_file) == ""
    env_file.write_text(f"GEMINI_API_KEY={GOOD_KEY}\n")          # the admin edits .env
    assert config.current_setting("GEMINI_API_KEY", path=env_file) == GOOD_KEY
    env_file.write_text("# key line removed\n")
    assert config.current_setting("GEMINI_API_KEY", path=env_file) == ""


def test_key_added_to_env_file_that_did_not_exist_at_start(env_file):
    config.load_env_file(env_file)                                # no file yet
    env_file.write_text(f'GEMINI_API_KEY="{GOOD_KEY}"\n')
    assert config.current_setting("GEMINI_API_KEY", path=env_file) == GOOD_KEY


# ---------------------------------------------------------------- provider
@pytest.mark.parametrize("pasted", [GOOD_KEY, f"  {GOOD_KEY}\n", f'"{GOOD_KEY}"', f"'{GOOD_KEY}' "])
def test_pasted_key_is_cleaned(pasted):
    assert clean_api_key(pasted) == GOOD_KEY
    assert GeminiProvider(api_key=pasted).api_key == GOOD_KEY


def test_model_choice_and_default(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert GeminiProvider(model_name=None, api_key="k").model_name == DEFAULT_GEMINI_MODEL
    monkeypatch.setenv("GEMINI_MODEL", "gemini-from-env")
    assert GeminiProvider(model_name=None, api_key="k").model_name == "gemini-from-env"
    # A model chosen in System Config wins over GEMINI_MODEL.
    p = GeminiProvider(model_name="models/gemini-chosen", api_key="k")
    assert p.model_name == "gemini-chosen"
    assert p.url.endswith("/models/gemini-chosen:generateContent")
    assert clean_model_name(" models/x-1 ") == "x-1"


def test_model_name_cannot_change_the_request_address():
    with pytest.raises(gemini_provider.LLMGatewayError):
        GeminiProvider(model_name="../../evil?x=1", api_key="k")


def test_rejected_key_gives_a_clear_message():
    problem, message = classify_gemini_error(400, INVALID_KEY_BODY.decode(), "m")
    assert problem == "key_rejected"
    assert "not valid" in message and "aistudio.google.com/apikey" in message
    assert classify_gemini_error(404, google_error(404, "not found", "NOT_FOUND").decode(), "m")[0] == "model_not_found"
    assert classify_gemini_error(403, google_error(403, "denied", "PERMISSION_DENIED").decode(), "m")[0] == "permission"


def test_generate_with_rejected_key_says_so(monkeypatch):
    def refuse(req, timeout):
        raise http_error(400, INVALID_KEY_BODY)
    monkeypatch.setattr(gemini_provider.urllib.request, "urlopen", refuse)
    with pytest.raises(gemini_provider.LLMGatewayError, match="API key is not valid"):
        GeminiProvider(model_name="gemini-x", api_key=BAD_KEY).generate("hello")


class FakeResponse:
    def __init__(self, data):
        self.data = json.dumps(data).encode()

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_generate_retries_without_json_mode_for_models_that_refuse_it(monkeypatch):
    sent = []

    def answer(req, timeout):
        body = json.loads(req.data)
        sent.append(body["generationConfig"])
        if "responseMimeType" in body["generationConfig"]:
            raise http_error(400, google_error(400, "JSON mode is not enabled for models/gemma-x", "INVALID_ARGUMENT"))
        return FakeResponse({"candidates": [{"content": {"parts": [{"text": "{}"}]}}]})

    monkeypatch.setattr(gemini_provider.urllib.request, "urlopen", answer)
    assert GeminiProvider(model_name="gemini-x", api_key=GOOD_KEY).generate("hi", format="json") == "{}"
    assert len(sent) == 2 and "responseMimeType" not in sent[1]


def test_check_gemini_uses_no_generation(monkeypatch):
    seen = {}

    def answer(req, timeout):
        seen["url"], seen["method"] = req.full_url, req.get_method()
        seen["key"] = req.get_header("X-goog-api-key")
        return FakeResponse({"name": "models/gemini-x", "displayName": "Gemini X"})

    monkeypatch.setattr(gemini_provider.urllib.request, "urlopen", answer)
    result = check_gemini(f" {GOOD_KEY} ", "gemini-x")
    assert result["ok"] and "Gemini X" in result["message"]
    assert seen == {"url": f"{gemini_provider.API_BASE}/models/gemini-x", "method": "GET", "key": GOOD_KEY}


def test_check_gemini_offline(monkeypatch):
    def offline(req, timeout):
        raise urllib.error.URLError("Name or service not known")
    monkeypatch.setattr(gemini_provider.urllib.request, "urlopen", offline)
    result = check_gemini(GOOD_KEY, "gemini-x")
    assert not result["ok"] and result["problem"] == "unreachable" and "Ollama" in result["message"]
    assert check_gemini("", "gemini-x")["problem"] == "no_key"


# ---------------------------------------------------------------- dashboard (System Config)
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


def fake_check(api_key, model, timeout=10):
    key = clean_api_key(api_key)
    if not key:
        return {"ok": False, "problem": "no_key", "message": "No Gemini API key is set."}
    if key == BAD_KEY:
        return {"ok": False, "problem": "key_rejected", "message": "Google says the Gemini API key is not valid."}
    if model == "no-such-model":
        return {"ok": False, "problem": "model_not_found", "message": "Google has no model called 'no-such-model'."}
    return {"ok": True, "problem": None, "message": "The key works."}


@pytest.fixture
def clients(monkeypatch):
    monkeypatch.setenv("LOAD_DOTENV", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setattr(main, "check_gemini", fake_check)
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    db = TestingSession()
    for role in ("admin", "investigator"):
        db.add(User(id=f"g_{role}", username=f"g_{role}", hashed_password=get_password_hash(PASSWORD),
                    role=role, allowed_datasets="ALL"))
    db.add(SystemConfig(key="llm_backend", value="gemini"))
    db.commit()
    db.close()
    result = {}
    for role in ("admin", "investigator"):
        client = TestClient(app)
        res = client.post("/api/v1/auth/login", json={"username": f"g_{role}", "password": PASSWORD})
        assert res.status_code == 200, res.text
        result[role] = client
    yield result
    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=engine)


def gateway_provider():
    db = TestingSession()
    try:
        provider, backend = main.get_llm_gateway(db)
        return provider
    finally:
        db.close()


def audit_text() -> str:
    db = TestingSession()
    try:
        return " ".join(entry.details for entry in db.query(AuditLog).all())
    finally:
        db.close()


def test_no_key_is_reported(clients):
    data = clients["admin"].get("/api/v1/admin/config").json()
    assert data["gemini"]["key_set"] is False and data["gemini"]["model"] == DEFAULT_GEMINI_MODEL


def test_saved_key_is_used_at_once_and_never_shown(clients):
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"api_key": f'  "{GOOD_KEY}" '})
    assert res.status_code == 200, res.text
    assert res.json()["check"]["ok"]
    view = clients["admin"].get("/api/v1/admin/config").json()["gemini"]
    assert view == {"key_set": True, "key_hint": "...wxyz", "key_source": "dashboard",
                    "model": DEFAULT_GEMINI_MODEL, "model_source": "default", "default_model": DEFAULT_GEMINI_MODEL}
    assert GOOD_KEY not in res.text and GOOD_KEY not in json.dumps(view)
    assert GOOD_KEY not in audit_text() and "...wxyz" in audit_text()
    assert gateway_provider().api_key == GOOD_KEY                       # no restart needed


def test_rejected_key_is_not_saved(clients):
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"api_key": BAD_KEY})
    assert res.status_code == 400 and "not valid" in res.json()["detail"]
    assert clients["admin"].get("/api/v1/admin/config").json()["gemini"]["key_set"] is False
    assert BAD_KEY not in audit_text()


def test_key_with_spaces_inside_is_refused(clients):
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"api_key": "AIza abc def"})
    assert res.status_code == 400 and "spaces" in res.json()["detail"]


def test_model_change_and_bad_model(clients):
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"model": "models/gemini-chosen"})
    assert res.status_code == 200, res.text                            # no key yet: model saved anyway
    assert clients["admin"].get("/api/v1/admin/config").json()["gemini"]["model"] == "gemini-chosen"
    assert gateway_provider().model_name == "gemini-chosen"
    clients["admin"].post("/api/v1/admin/config/gemini", json={"api_key": GOOD_KEY})
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"model": "no-such-model"})
    assert res.status_code == 400
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"model": "bad/name"})
    assert res.status_code == 400


def test_removing_saved_key_falls_back_to_env(clients, monkeypatch):
    clients["admin"].post("/api/v1/admin/config/gemini", json={"api_key": GOOD_KEY})
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTEST-env-key-000000000000000envk")
    res = clients["admin"].post("/api/v1/admin/config/gemini", json={"api_key": ""})
    assert res.status_code == 200
    view = res.json()["gemini"]
    assert view["key_source"] == "env" and view["key_hint"] == "...envk"
    assert gateway_provider().api_key.endswith("envk")


def test_test_endpoint_checks_without_saving(clients):
    res = clients["admin"].post("/api/v1/admin/config/gemini/test", json={"api_key": GOOD_KEY})
    assert res.json()["ok"] is True
    assert clients["admin"].get("/api/v1/admin/config").json()["gemini"]["key_set"] is False
    assert clients["admin"].post("/api/v1/admin/config/gemini/test", json={}).json()["problem"] == "no_key"


def test_only_admins_can_see_or_change_gemini_settings(clients):
    assert clients["investigator"].get("/api/v1/admin/config").status_code == 403
    assert clients["investigator"].post("/api/v1/admin/config/gemini", json={"api_key": GOOD_KEY}).status_code == 403
    assert clients["investigator"].post("/api/v1/admin/config/gemini/test", json={}).status_code == 403


def test_switching_to_gemini_without_key_warns(clients):
    res = clients["admin"].post("/api/v1/admin/config", json={"llm_backend": "gemini"})
    assert res.status_code == 200 and "no API key" in res.json()["warning"]
