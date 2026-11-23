"""
When the threat retrieval service cannot search, an investigation must say so - never report
"no matching records", which would tell the investigator the report is clear when it was never
checked. A real empty result still gives the honest "Unsupported" verdict.

Run:  python -m pytest tests/test_investigator_retrieval.py -v
"""
import io
import json
import os
import urllib.error

os.environ["LOAD_DOTENV"] = "0"
os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest                                 # noqa: E402
from fastapi.testclient import TestClient     # noqa: E402
from sqlalchemy import create_engine          # noqa: E402
from sqlalchemy.orm import sessionmaker       # noqa: E402
from sqlalchemy.pool import StaticPool        # noqa: E402

from backend.api import main                  # noqa: E402
from backend.api.main import app, get_db, get_llm_gateway   # noqa: E402
from backend.auth.passwords import get_password_hash        # noqa: E402
from backend.database import Base             # noqa: E402
from backend.models import AuditLog, User     # noqa: E402
from llm import RetrievalUnavailableError     # noqa: E402
from llm.gateway.factory import MockLLMProvider              # noqa: E402
from llm.workflows import investigator as inv  # noqa: E402

URL = "http://retrieval.test:8000"


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def refuse_with(exc):
    def urlopen(req, timeout):
        raise exc
    return urlopen


def investigate(**kw):
    return inv.ThreatInvestigator(provider=MockLLMProvider()).investigate(
        "EternalBlue SMB exploitation", team2_api_url=URL, **kw)


@pytest.mark.parametrize("exc, words", [
    (urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")), "cannot be reached"),
    (urllib.error.URLError("timed out"), "cannot be reached"),
    (TimeoutError("timed out"), "cannot be reached"),
    (urllib.error.HTTPError(URL, 503, "busy", {}, io.BytesIO(b"{}")), "still starting"),
    (urllib.error.HTTPError(URL, 500, "error", {}, io.BytesIO(b"{}")), "HTTP 500"),
])
def test_search_that_did_not_run_is_an_error_not_no_match(monkeypatch, exc, words):
    monkeypatch.setattr(inv.urllib.request, "urlopen", refuse_with(exc))
    with pytest.raises(RetrievalUnavailableError, match=words):
        investigate()


def test_answer_that_is_not_json_is_an_error(monkeypatch):
    monkeypatch.setattr(inv.urllib.request, "urlopen", lambda req, timeout: FakeResponse(b"<html>proxy error</html>"))
    with pytest.raises(RetrievalUnavailableError, match="not JSON"):
        investigate()


def test_real_empty_result_is_still_an_honest_no_match(monkeypatch):
    monkeypatch.setattr(inv.urllib.request, "urlopen",
                        lambda req, timeout: FakeResponse(json.dumps({"top_matches": []}).encode()))
    result = investigate()
    assert result.match_status == "Unsupported"


def test_long_report_is_searched_on_its_beginning(monkeypatch):
    sent = {}

    def urlopen(req, timeout):
        sent["query"] = json.loads(req.data)["query"]
        return FakeResponse(json.dumps({"top_matches": []}).encode())

    monkeypatch.setattr(inv.urllib.request, "urlopen", urlopen)
    inv.ThreatInvestigator(provider=MockLLMProvider()).investigate("A" * 50000, team2_api_url=URL)
    assert len(sent["query"]) == inv.MAX_QUERY_CHARS == 40960


# ------------------------------------------------------------------ the web app's answer
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
PASSWORD = "investigator-retrieval-test-password"


def _db():
    db = Session()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def clients(monkeypatch):
    monkeypatch.setenv("TEAM2_API_URL", URL)
    monkeypatch.setattr(inv.urllib.request, "urlopen",
                        refuse_with(urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))))
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_llm_gateway] = lambda: (MockLLMProvider(), "gemini")
    Base.metadata.create_all(bind=engine)
    db = Session()
    for role in ("investigator", "admin"):
        db.add(User(id=f"r_{role}", username=f"r_{role}", hashed_password=get_password_hash(PASSWORD),
                    role=role, allowed_datasets="ALL"))
    db.commit()
    db.close()
    out = {}
    for role in ("investigator", "admin"):
        c = TestClient(app)
        assert c.post("/api/v1/auth/login", json={"username": f"r_{role}", "password": PASSWORD}).status_code == 200
        out[role] = c
    yield out
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_llm_gateway, None)
    Base.metadata.drop_all(bind=engine)


BODY = {"correlation_id": "00000000-0000-4000-8000-000000000001", "entities": ["CVE-2017-0144", "EternalBlue"]}


def test_web_app_says_matching_is_unavailable(clients):
    res = clients["investigator"].post("/api/v1/investigation/threats", json=BODY)
    assert res.status_code == 503 and res.headers.get("Retry-After") == "30"
    detail = res.json()["detail"]
    assert "retrieval service cannot be reached or is still starting" in detail and "Reference:" in detail
    assert "No matching" not in detail
    assert URL not in detail                          # internal address only for admins
    admin_detail = clients["admin"].post("/api/v1/investigation/threats", json=BODY).json()["detail"]
    assert URL in admin_detail
    db = Session()
    try:
        entry = db.query(AuditLog).filter(AuditLog.action == "threat_match").first()
        details = json.loads(entry.details)
        assert details["outcome"] == "failure" and details["stage"] == "retrieval"
    finally:
        db.close()
