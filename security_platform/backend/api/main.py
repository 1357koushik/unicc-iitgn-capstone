import hashlib
import logging
import math
import mimetypes
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import timezone
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Response, Request, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Literal, Optional

from backend.config import get_bool, get_int, get_str   # loads the .env file first
from backend.database import engine, Base, get_db
from backend.models import User, SystemConfig
from backend.auth.auth_service import (
    DBUserStore, create_jwt_token, require_role, TOKEN_EXPIRE_MINUTES,
    UnauthorizedError, ForbiddenError
)
from backend.auth.passwords import PUBLISHED_DEFAULT_PASSWORDS
from backend.auth.login_limiter import LoginLimiter
from backend.auth.sessions import SessionEndedError, check_session, revoke_token
from backend.manage_users import create_initial_accounts
from backend.audit.audit_service import log_action, get_audit_logs
from backend.ingest.file_extractor import (
    ALLOWED_EXTENSIONS, FileExtractionError, ReportTooLongError, extract_text, file_extension
)
from llm import summarize_report, extract_entities as llm_extract, investigate_threat, get_llm_provider
from llm import RetrievalUnavailableError
from llm.gateway.interface import LLMGatewayError, LLMTimeoutError
from llm.gateway.ioc_extractor import extract_iocs
from llm.gateway.api.gemini_provider import check_gemini, clean_api_key, clean_model_name, valid_model_name
from backend import gemini_settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    # First start with an empty database: create the demo accounts with RANDOM
    # passwords and show them once in this window. No password is written in the code.
    db = next(get_db())
    created = create_initial_accounts(db)
    if created:
        log = logging.getLogger("uvicorn.error")
        log.warning("No user accounts existed, so these were created. The passwords are shown ONLY ONCE - write them down now:")
        for username, role, password in created:
            log.warning(f"    username: {username:<16} password: {password}   ({role})")
        log.warning("To change a password later: python -m backend.manage_users reset-password <username>")

    if not db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first():
        # First start: which AI backend to use until an admin changes it in System Config.
        first_backend = get_str("DEFAULT_LLM_BACKEND", "gemini")
        if first_backend not in ("gemini", "ollama"):
            raise RuntimeError("DEFAULT_LLM_BACKEND must be 'gemini' or 'ollama'.")
        db.add(SystemConfig(key="llm_backend", value=first_backend))
        
    db.commit()
    for warning in _settings_warnings(db):
        logging.getLogger("uvicorn.error").warning(warning)
    db.close()
    yield


def _settings_warnings(db: Session) -> List[str]:
    """Settings that are fine for testing on this computer but not for real use."""
    warnings = []
    if not get_bool("COOKIE_SECURE", False):
        warnings.append("COOKIE_SECURE is off: fine at http://127.0.0.1, but turn it on when the app is served over HTTPS.")
    backend = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    if backend and backend.value == "gemini" and not gemini_settings.current(db)["api_key"]:
        warnings.append("No Gemini API key is set: AI summaries will fail until an admin pastes one in "
                        "System Config (or sets GEMINI_API_KEY in .env), or switches to Ollama.")
    return warnings

app = FastAPI(title="UNICC Cyber AI Gateway", lifespan=lifespan)

def _size_limit(path: str):
    """The largest request allowed on this address, and the message shown when it is exceeded."""
    if path == UPLOAD_PATH:
        return MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES, (
            f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB). Split the report, or paste its text instead.")
    if path in (NETWORK_SCAN_PATH, NETWORK_LIVE_START_PATH, NETWORK_ALERTS_CSV_PATH):
        return MAX_NETWORK_FILE_BYTES + MULTIPART_OVERHEAD_BYTES, (
            f"File too large (limit {MAX_NETWORK_FILE_BYTES // (1024 * 1024)} MB). Split the file.")
    return MAX_BODY_BYTES, (
        f"Request too large (limit {MAX_BODY_BYTES // (1024 * 1024)} MB). Shorten the report or split it.")


class LimitRequestSize:
    """
    Refuse oversized requests, so one huge upload can't fill the server's memory or disk.

    Two checks, because a request can arrive in two ways:
    - it announces its size up front (Content-Length): refused at once, before any of it is read;
    - it arrives in pieces without announcing a size ("chunked"): the bytes are counted as they
      arrive, and the request is stopped as soon as it goes over the limit. Checking only the
      announced size would let such a request through at any size.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit, message = _size_limit(scope.get("path", ""))

        length = dict(scope.get("headers") or []).get(b"content-length", b"")
        if length.isdigit() and int(length) > limit:
            return await JSONResponse(status_code=413, content={"detail": message})(scope, receive, send)

        received = 0

        async def counting_receive():
            nonlocal received
            event = await receive()
            if event["type"] == "http.request":
                received += len(event.get("body", b""))
                if received > limit:
                    raise HTTPException(status_code=413, detail=message)
            return event

        await self.app(scope, counting_receive, send)


app.add_middleware(LimitRequestSize)


@app.middleware("http")
async def set_cache_rules(request: Request, call_next):
    """
    Tell browsers how to cache what we send.

    - API answers (/api/...) contain investigation data and audit logs:
      "no-store" means the browser must never keep a copy on disk.
    - Dashboard files (index.html, app.js, style.css): "no-cache" means the
      browser may keep a copy but must ask the server before each use. The
      server answers "not changed" (304) when it is still current, so this is
      cheap - and after an update every user gets the new version at once.
    """
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


# Browser security rules sent with every answer. They add protection in the
# browser itself, on top of what the server and dashboard code already do.
#
# Content-Security-Policy - which files the page may use. "Only this app's own
#   files": no scripts or styles written inside the page, nothing from other
#   websites, no plug-ins. So even if a report managed to slip code into the page
#   (XSS), the browser would refuse to run it. The dashboard is written to follow
#   this: no inline scripts, styles or onclick="..." attributes (a test checks it).
# frame-ancestors / X-Frame-Options - no other website may show the dashboard
#   inside its own page. That stops "clickjacking": showing it invisibly and
#   tricking an investigator into clicking, for example, Submit Decision.
# X-Content-Type-Options - the browser must use the file type we state, never
#   guess one (a guess could turn text into a runnable script).
# Referrer-Policy - addresses inside the app are never sent to other websites.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
# The API reference pages (/docs, /redoc) are made by FastAPI and load their code
# from a public website (a CDN), which the strict rule above would block. They get
# every rule except that one. The dashboard itself always gets the strict rule.
_API_REFERENCE_PAGES = ("/docs", "/redoc")


class SecurityHeaders:
    """Adds the browser security rules above to every answer the app sends."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(SECURITY_HEADERS)
        if not scope.get("path", "").startswith(_API_REFERENCE_PAGES):
            headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        else:
            headers["Content-Security-Policy"] = "frame-ancestors 'none'"

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                present = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(name.lower().encode(), value.encode()) for name, value in headers.items()
                         if name.lower().encode() not in present]
                message = {**message, "headers": list(message.get("headers", [])) + extra}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeaders)


# Which OTHER websites may call this API from a user's browser (CORS).
# The dashboard is served by this same app, so it needs no permission, and by
# default NO other website is allowed. If the dashboard is ever hosted at a
# different address, list that address in ALLOWED_ORIGINS, e.g.
#     ALLOWED_ORIGINS=https://dashboard.example.org
def _load_allowed_origins() -> List[str]:
    origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if "*" in origins:
        raise RuntimeError("ALLOWED_ORIGINS must list specific addresses, not '*' (that would allow every website).")
    return origins

_allowed_origins = _load_allowed_origins()
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

# Exception handlers for Custom Auth errors
@app.exception_handler(UnauthorizedError)
async def unauthorized_handler(request: Request, exc: UnauthorizedError):
    return JSONResponse(status_code=401, content={"detail": str(exc)})

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    """Last safety net: never show a crash's internals to the user."""
    ref = _new_error_reference()
    _server_log.error(f"[error ref {ref}] Unexpected error on {request.method} {request.url.path}",
                      exc_info=(type(exc), exc, exc.__traceback__))
    return JSONResponse(status_code=500, content={
        "detail": f"Something went wrong on the server. Reference: {ref} - an administrator can find the details in the server log."})

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Turn "the input broke a rule" errors into one readable sentence for the dashboard."""
    messages = []
    for error in exc.errors()[:3]:
        field = ".".join(str(part) for part in error.get("loc", []) if part != "body")
        messages.append(f"{field}: {error.get('msg', 'invalid value')}" if field else error.get("msg", "invalid value"))
    return JSONResponse(status_code=422, content={"detail": "Invalid input - " + "; ".join(messages)})

@app.exception_handler(ForbiddenError)
async def forbidden_handler(request: Request, exc: ForbiddenError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})

# Counts failed logins to stop password guessing (see backend/auth/login_limiter.py).
login_limiter = LoginLimiter(
    max_failures_per_user=get_int("LOGIN_MAX_FAILURES_PER_USER", 5),
    max_failures_per_ip=get_int("LOGIN_MAX_FAILURES_PER_IP", 20),     # 0 = off (see login_limiter.py)
    window_seconds=get_int("LOGIN_BLOCK_MINUTES", 15) * 60,
)

ALL_ROLES = ["investigator", "auditor", "admin"]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# --- Dependencies ---
def get_current_user_token(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise UnauthorizedError("Not authenticated")
    return token

def get_session_user(token: str = Depends(get_current_user_token), db: Session = Depends(get_db)) -> dict:
    """A valid pass (signature and expiry) whose session has not been ended."""
    user = require_role(token, ALL_ROLES)
    try:
        check_session(db, user)
    except SessionEndedError as ended:
        raise UnauthorizedError(str(ended))
    return user

def _require(user: dict, roles: List[str]) -> dict:
    if user.get("role") not in roles:
        raise ForbiddenError(f"Your role ({user.get('role')}) is not allowed to do this.")
    return user

def get_investigator_user(user: dict = Depends(get_session_user)):
    return _require(user, ["investigator", "admin"])

def get_admin_user(user: dict = Depends(get_session_user)):
    return _require(user, ["admin"])

def get_auditor_user(user: dict = Depends(get_session_user)):
    return _require(user, ["auditor", "admin"])

class _UnavailableGateway:
    """Stands in for an AI backend that could not be set up, so that failure is
    handled exactly like any other AI failure (safe message, audit entry)."""
    def __init__(self, reason: str):
        self.reason = reason

    def _fail(self, *args, **kwargs):
        raise LLMGatewayError(self.reason)

    summarize_report = extract_entities = investigate_synthesis = _fail


def get_llm_gateway(db: Session = Depends(get_db)):
    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    backend = config.value if config else "gemini"
    try:
        if backend == "ollama":
            provider = get_llm_provider(backend="local")
        else:
            # Read the key and model for EVERY request, so a key saved in System Config
            # (or in .env) is used at once, without a restart.
            gemini = gemini_settings.current(db)
            provider = get_llm_provider(backend="gemini", model_name=gemini["model"], api_key=gemini["api_key"])
        return provider, backend
    except Exception as e:
        return _UnavailableGateway(f"The '{backend}' backend could not be set up: {e}"), backend


_server_log = logging.getLogger("uvicorn.error")


def _new_error_reference() -> str:
    return secrets.token_hex(4).upper()


def _ai_failure(db: Session, user: dict, correlation_id: str, action: str, backend_name: str, error: Exception) -> HTTPException:
    """
    Record an AI failure in full for admins, and return a SAFE message for the user.

    Raw errors can reveal internal addresses, library names or the AI provider's own
    replies - useful to an attacker, useless to an investigator. The full text goes to
    the server log and the audit log under a short reference code; the user sees the
    code, which an administrator can look up. Admins also see the details directly.
    """
    ref = _new_error_reference()
    _server_log.error(f"[error ref {ref}] {action} failed with the '{backend_name}' AI backend: {error}")
    log_action(db, correlation_id, user["id"], user["role"], action, "doc_current", backend_name, "failure",
               {"error": str(error)[:2000], "error_ref": ref})

    timed_out = isinstance(error, LLMTimeoutError)
    message = ("The AI model took too long to answer. Please try again." if timed_out
               else "The AI model could not produce an answer right now.")
    if user.get("role") == "admin":
        message += f" Details (shown to admins only): {str(error)[:500]}"
    message += f" Reference: {ref} - an administrator can find the details in the server and audit logs."
    return HTTPException(status_code=504 if timed_out else 502, detail=message)

def _retrieval_failure(db: Session, user: dict, correlation_id: str, backend_name: str,
                       error: Exception) -> HTTPException:
    """
    The threat retrieval service could not search. Reported as an error (503), never as
    "no match": an empty result would tell the investigator the report is clear when it
    was never checked. Logged in full for admins, like an AI failure.
    """
    ref = _new_error_reference()
    _server_log.error(f"[error ref {ref}] threat_match: retrieval service unavailable: {error}")
    log_action(db, correlation_id, user["id"], user["role"], "threat_match", "doc_current", backend_name, "failure",
               {"error": str(error)[:2000], "error_ref": ref, "stage": "retrieval"})
    message = ("Threat matching is not available right now: the threat retrieval service cannot be reached "
               "or is still starting (after a restart it needs 1-3 minutes). Please try again shortly.")
    if user.get("role") == "admin":
        message += f" Details (shown to admins only): {str(error)[:500]}"
    message += f" Reference: {ref} - an administrator can find the details in the server and audit logs."
    return HTTPException(status_code=503, detail=message, headers={"Retry-After": "30"})

# --- Input limits ---
# Every request is checked against these before the app does any work with it.
MAX_REPORT_CHARS = 2_000_000          # roughly a 50-60 page report
MAX_EVIDENCE_CHARS = MAX_REPORT_CHARS + 200_000
MAX_NOTES_CHARS = 50_000
MAX_ENTITIES = 5000
MAX_ENTITY_CHARS = 5120
MAX_BODY_BYTES = 20 * 1024 * 1024    # 2 MB for any single request...
MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # ...except a report file: PDFs with pictures are often several MB
MULTIPART_OVERHEAD_BYTES = 64 * 1024 # the few extra bytes a browser adds around an uploaded file
UPLOAD_PATH = "/api/v1/investigation/upload"
# Network sensor (Task 5.0): a file of connection records to check for attacks
NETWORK_SCAN_PATH = "/api/v1/network/scan"
NETWORK_LIVE_START_PATH = "/api/v1/network/live/start"
NETWORK_ALERTS_CSV_PATH = "/api/v1/network/scan/alerts.csv"   # every alert of a file, for download
MAX_NETWORK_FILE_BYTES = 50 * 1024 * 1024    # the whole NSL-KDD test file (3.4 MB) fits
NETWORK_FILE_EXTENSIONS = {".csv", ".txt"}
CORRELATION_ID = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")

# --- Pydantic Schemas ---
class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)

class AnalyzeRequest(BaseModel):
    report_text: str = Field(min_length=1, max_length=MAX_REPORT_CHARS)

class EntitiesRequest(BaseModel):
    report_text: str = Field(min_length=1, max_length=MAX_REPORT_CHARS)
    correlation_id: str = CORRELATION_ID

class ThreatsRequest(BaseModel):
    entities: List[str] = Field(max_length=MAX_ENTITIES)
    context: Optional[str] = None
    correlation_id: str = CORRELATION_ID

class SummarizeRequest(BaseModel):
    evidence: str = Field(min_length=1, max_length=MAX_EVIDENCE_CHARS)
    correlation_id: str = CORRELATION_ID

class DecisionRequest(BaseModel):
    decision: Literal["escalate", "monitor", "dismiss"]    # only the choices the dashboard offers
    notes: str = Field(default="", max_length=MAX_NOTES_CHARS)
    correlation_id: str = CORRELATION_ID

class ConfigUpdate(BaseModel):
    llm_backend: str = Field(max_length=32)

class GeminiConfigUpdate(BaseModel):
    # Both optional: send only what changes. An empty string removes the dashboard
    # value, so the one in .env is used again.
    api_key: Optional[str] = Field(default=None, max_length=256)
    model: Optional[str] = Field(default=None, max_length=128)

class GeminiTestRequest(BaseModel):
    # Test a key before saving it; empty = test the key and model in use now.
    api_key: Optional[str] = Field(default=None, max_length=256)
    model: Optional[str] = Field(default=None, max_length=128)

class UserUpdate(BaseModel):
    allowed_datasets: str

class PoCFindRequest(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$")
    max_results: int = Field(default=20, ge=1, le=1000)
    sources: Optional[List[str]] = None
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)

# --- Endpoints ---
@app.get("/api/v1/admin/users")
def get_users(user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "role": u.role, "allowed_datasets": u.allowed_datasets} for u in users]

@app.put("/api/v1/admin/users/{user_id}/permissions")
def update_user_permissions(user_id: str, req: UserUpdate, admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    target_user.allowed_datasets = req.allowed_datasets
    db.commit()
    log_action(db, "admin", admin["id"], admin["role"], "update_permissions", "users", "none", "success", {"target_user": target_user.username, "new_datasets": req.allowed_datasets})
    return {"message": "Permissions updated"}

@app.post("/api/v1/auth/login")
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    # Recorded in the audit log for failed attempts. Never the password.
    attempt = {"attempted_username": req.username[:64], "ip": ip}

    # 1) Too many recent failures for this username or this computer? Refuse without checking.
    wait_seconds = login_limiter.seconds_until_allowed(req.username, ip)
    if wait_seconds:
        log_action(db, "auth", "anonymous", "none", "login_blocked", "auth", "none", "failure",
                   {**attempt, "retry_after_seconds": wait_seconds})
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in {math.ceil(wait_seconds / 60)} minute(s).",
            headers={"Retry-After": str(wait_seconds)},
        )

    # 2) Passwords that were public in the project's code are never accepted.
    if req.password in PUBLISHED_DEFAULT_PASSWORDS:
        login_limiter.record_failure(req.username, ip)
        log_action(db, "auth", "anonymous", "none", "login_failed", "auth", "none", "failure",
                   {**attempt, "reason": "published default password"})
        raise HTTPException(
            status_code=401,
            detail="This password was published in the project's code and is no longer accepted. "
                   "An admin can set a new one with: python -m backend.manage_users reset-password <username>",
        )

    # 3) Normal check.
    user = DBUserStore(db).authenticate(req.username, req.password)
    if not user:
        login_limiter.record_failure(req.username, ip)
        log_action(db, "auth", "anonymous", "none", "login_failed", "auth", "none", "failure",
                   {**attempt, "reason": "invalid credentials"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_limiter.record_success(req.username)
    log_action(db, "auth", user["id"], user["role"], "login", "auth", "none", "success", {"ip": ip})

    token = create_jwt_token(user)
    response.set_cookie(
        key="access_token", 
        value=token, 
        httponly=True, 
        max_age=TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=get_bool("COOKIE_SECURE", False),   # True when served over HTTPS (see .env.example)
    )
    return {"message": "Logged in successfully", "role": user["role"]}

@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if token:
        try:
            user = require_role(token, ALL_ROLES)
            check_session(db, user)
            revoke_token(db, user)   # this pass is refused from now on, even if someone copied it
            log_action(db, "auth", user["id"], user["role"], "logout", "auth", "none", "success",
                       {"ip": _client_ip(request)})
        except (UnauthorizedError, ForbiddenError, SessionEndedError):
            pass  # an expired, invalid or already-ended pass: nothing to record, just clear the cookie
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}

@app.get("/api/v1/auth/me")
def who_am_i(user: dict = Depends(get_session_user)):
    """Lets the dashboard ask "am I still logged in, and as whom?" (e.g. after a page refresh)."""
    return {"username": user.get("username"), "role": user.get("role")}

@app.get("/api/v1/admin/audit-logs")
def api_get_audit_logs(user: dict = Depends(get_auditor_user), db: Session = Depends(get_db)):
    # Looking at the audit log is itself recorded. This is done FIRST: saving a new
    # entry clears rows already loaded in this session, which would send them empty.
    log_action(db, "admin", user["id"], user["role"], "view_audit_logs", "audit_log", "none", "success")
    usernames = {u.id: u.username for u in db.query(User).all()}
    return [
        {
            "id": entry.id,
            # Stored in UTC; the "+00:00" label lets each browser convert it to local time.
            "timestamp": entry.timestamp.replace(tzinfo=timezone.utc).isoformat(),
            "action": entry.action,
            "user": entry.user,
            "username": usernames.get(entry.user, entry.user),
            "role": entry.role,
            "correlation_id": entry.correlation_id,
            "details": entry.details,
        }
        for entry in get_audit_logs(db)
    ]

@app.get("/api/v1/admin/config")
def api_get_config(user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    return {"llm_backend": config.value if config else "gemini", "gemini": gemini_settings.public_view(db)}


def _check_key_text(raw: str) -> str:
    key = clean_api_key(raw)
    if key and (any(ch.isspace() for ch in key) or not key.isprintable()):
        raise HTTPException(status_code=400, detail="The API key contains spaces or invisible characters. "
                                                    "Copy it again from https://aistudio.google.com/apikey.")
    return key


def _check_model_text(raw: str) -> str:
    model = clean_model_name(raw)
    if model and not valid_model_name(model):
        raise HTTPException(status_code=400, detail="The model name may only contain letters, digits, '.', '_' and '-'.")
    return model


# Google answers that mean the key or model is wrong: such settings are not saved.
# (If Google simply cannot be reached, the settings ARE saved, with a warning.)
_GEMINI_REJECTIONS = ("key_rejected", "permission", "model_not_found", "bad_model_name")


@app.post("/api/v1/admin/config/gemini")
def api_update_gemini_config(req: GeminiConfigUpdate, user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    """
    Save the Gemini API key and/or model in the app's database. They are used at once.
    A new key is first checked with Google; a key Google rejects is not saved.
    """
    if req.api_key is None and req.model is None:
        raise HTTPException(status_code=400, detail="Nothing to save: send api_key and/or model.")
    key = _check_key_text(req.api_key) if req.api_key is not None else None
    model = _check_model_text(req.model) if req.model is not None else None

    check = None
    if key or model:
        # Check what will be in use after saving: the new key with the new (or current) model.
        after = gemini_settings.current(db, key=key, model=model)
        check = check_gemini(after["api_key"], after["model"])
        if not check["ok"] and check["problem"] in _GEMINI_REJECTIONS:
            log_action(db, "admin", user["id"], user["role"], "config_change", "system_config", "gemini", "failure",
                       {"setting": "gemini", "reason": check["problem"]})
            raise HTTPException(status_code=400, detail=f"Not saved: {check['message']}")

    changed = {}
    if key is not None:
        gemini_settings.store(db, gemini_settings.KEY_SETTING, key)
        changed["api_key"] = gemini_settings.key_hint(key) if key else "removed (using .env)"
    if model is not None:
        gemini_settings.store(db, gemini_settings.MODEL_SETTING, model)
        changed["model"] = model or "removed (using .env)"
    # Audit entry: which settings changed - the key only as its last 4 characters.
    log_action(db, "admin", user["id"], user["role"], "config_change", "system_config", "gemini", "success",
               {"setting": "gemini", "changed": changed})
    return {"message": "Gemini settings saved", "check": check, "gemini": gemini_settings.public_view(db)}


@app.post("/api/v1/admin/config/gemini/test")
def api_test_gemini_config(req: GeminiTestRequest, user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Ask Google whether a key and model work (the given ones, else the ones in use). Saves nothing."""
    now = gemini_settings.current(db)
    key = _check_key_text(req.api_key or "") or now["api_key"]
    model = _check_model_text(req.model or "") or now["model"]
    return check_gemini(key, model)

@app.post("/api/v1/admin/config")
def api_update_config(req: ConfigUpdate, user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    if req.llm_backend not in ["gemini", "ollama"]:
        log_action(db, "admin", user["id"], user["role"], "config_change", "system_config", "none", "failure",
                   {"setting": "llm_backend", "rejected_value": req.llm_backend[:64]})
        raise HTTPException(status_code=400, detail="Invalid backend")

    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    old_value = config.value if config else None
    if config:
        config.value = req.llm_backend
    else:
        db.add(SystemConfig(key="llm_backend", value=req.llm_backend))
    db.commit()
    log_action(db, "admin", user["id"], user["role"], "config_change", "system_config", "none", "success",
               {"setting": "llm_backend", "old_value": old_value, "new_value": req.llm_backend})
    response = {"message": "Config updated"}
    if req.llm_backend == "gemini" and not gemini_settings.current(db)["api_key"]:
        response["warning"] = "Gemini is selected but no API key is set yet: add one below."
    return response


@app.post("/api/v1/investigation/analyze")
def analyze_report(req: AnalyzeRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    # Simply generates a correlation_id and returns the text
    correlation_id = str(uuid.uuid4())
    # The fingerprint (hash) of the text links this investigation to an uploaded file's
    # audit entry, without storing the report itself in the audit log.
    log_action(db, correlation_id, user["id"], user["role"], "upload_report", "doc_new", "none", "success",
               {"characters": len(req.report_text), "text_sha256": _sha256(req.report_text.encode("utf-8"))})
    return {"correlation_id": correlation_id, "text": req.report_text}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_filename(name: str) -> str:
    """The file's name as the user's computer sent it: printable characters only, shortened."""
    return "".join(ch for ch in (name or "") if ch.isprintable())[:128] or "(no name)"


@app.post(UPLOAD_PATH)
def upload_report_file(file: UploadFile = File(...), user: dict = Depends(get_investigator_user),
                       db: Session = Depends(get_db)):
    """
    Read a report from an uploaded .txt, .pdf or .docx file and return its text.

    It only returns the text: the dashboard puts it in the paste box, the investigator
    can check or edit it, and the analysis starts the same way as for pasted text.
    The file itself is not kept. Its name and fingerprints (hashes) go in the audit log.

    (A plain "def", not "async def": reading a PDF takes real work, and FastAPI runs a
    plain function in a separate thread, so other users are not kept waiting meanwhile.)
    """
    filename = _safe_filename(file.filename)
    content = file.file.read(MAX_UPLOAD_BYTES + 1)
    details = {"filename": filename, "file_bytes": len(content), "file_sha256": _sha256(content)}

    def refuse(status: int, reason: str):
        log_action(db, "upload", user["id"], user["role"], "upload_report_file", "doc_new", "none", "failure",
                   {**details, "reason": reason[:256]})
        raise HTTPException(status_code=status, detail=reason)

    if len(content) > MAX_UPLOAD_BYTES:
        refuse(413, f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB). "
                    "Split the report, or paste its text instead.")
    if file_extension(filename) not in ALLOWED_EXTENSIONS:
        refuse(415, f"Files of type '{file_extension(filename) or 'unknown'}' can't be uploaded. "
                    f"Accepted formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}.")
    try:
        text = extract_text(filename, content, MAX_REPORT_CHARS)
    except ReportTooLongError as e:
        refuse(413, str(e))
    except FileExtractionError as e:
        refuse(400, str(e))
    except Exception as e:
        # A problem inside a file-reading library: the file is refused like any other
        # unreadable file; the technical details go to the server log only.
        ref = _new_error_reference()
        _server_log.error(f"[error ref {ref}] Reading uploaded file failed: {type(e).__name__}: {e}")
        refuse(400, f"This file could not be read. Reference: {ref}")

    log_action(db, "upload", user["id"], user["role"], "upload_report_file", "doc_new", "none", "success",
               {**details, "characters": len(text), "text_sha256": _sha256(text.encode("utf-8"))})
    return {"text": text, "filename": filename, "characters": len(text)}

@app.post("/api/v1/investigation/entities")
def extract_entities(req: EntitiesRequest, user: dict = Depends(get_investigator_user),
                     db: Session = Depends(get_db), gw_dep = Depends(get_llm_gateway)):
    provider, backend_name = gw_dep
    res = extract_iocs(req.report_text)
    
    try:
        llm_result = llm_extract(req.report_text, provider=provider)
        res["threat_actors"] = llm_result.get("threat_actors", [])
        res["malware_families"] = llm_result.get("malware_families", [])
    except Exception as e:
        print("Entity Extraction LLM Error:", repr(e))
        pass
    log_action(db, req.correlation_id, user["id"], user["role"], "extract_entities", "doc_current", backend_name, "success")
    return res

@app.post("/api/v1/investigation/threats")
def get_threat_matches(req: ThreatsRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db), gw_dep = Depends(get_llm_gateway)):
    provider, backend_name = gw_dep
    if any(len(entity) > MAX_ENTITY_CHARS for entity in req.entities):
        raise HTTPException(status_code=422, detail=f"Invalid input - each entity must be at most {MAX_ENTITY_CHARS} characters.")
    
    try:
        obs_text = "\n".join(req.entities) if req.entities else (req.context or "")
        allowed_sources_str = user.get("allowed_datasets", "ALL")
        allowed_sources = None if allowed_sources_str == "ALL" else [s.strip() for s in allowed_sources_str.split(",")]
        
        retrieval_default = "http://retrieval:8000" if os.path.exists("/.dockerenv") else "http://localhost:8000"
        result = investigate_threat(
            observation=obs_text,
            provider=provider,
            team2_api_url=os.getenv("TEAM2_API_URL", retrieval_default),
            allowed_sources=allowed_sources
        )
        
        frontend_matches = []
        if result.get("match_status") != "Unsupported":
            patch = result.get("patch_details") or {}
            patch_status = patch.get("patch_status", "N/A")
            threat = f"Status: {result.get('match_status')} | Patch: {patch_status} | Threat Actors: {', '.join(result.get('potential_threat_actors', []))} | CVEs: {', '.join(result.get('associated_cves', []))}"
            frontend_matches.append({
                "threat": threat,
                "confidence": result.get("confidence_level", "Medium"),
                "mitre_tactics": result.get("associated_mitre_tactics") or result.get("mitre_tactics") or [],
                "associated_malware": result.get("associated_malware", []),
                "citations": result.get("supporting_citations", []),
                "patch_details": patch
            })
            
        res = {
            "matches": frontend_matches,
            "status": "success",
            "message": result.get("assessment_narrative", "")
        }
        
        log_action(db, req.correlation_id, user["id"], user["role"], "threat_match", "doc_current", backend_name, "success")
        return res
    except RetrievalUnavailableError as e:
        raise _retrieval_failure(db, user, req.correlation_id, backend_name, e)
    except LLMGatewayError as e:
        raise _ai_failure(db, user, req.correlation_id, "threat_match", backend_name, e)
    except Exception as e:
        raise _ai_failure(db, user, req.correlation_id, "threat_match", backend_name, e)

@app.post("/api/v1/llm/summarize")
def summarize_investigation(req: SummarizeRequest, user: dict = Depends(get_investigator_user), 
                            db: Session = Depends(get_db), gw_dep = Depends(get_llm_gateway)):
    provider, backend_name = gw_dep
    try:
        result = summarize_report(req.evidence, provider=provider)
        res = {
            "summary": result.get("executive_summary", ""),
            "key_points": [
                f"Title: {result.get('title', '')}",
                f"Threat Level: {result.get('threat_level', '')}",
                f"Affected Products: {', '.join(result.get('affected_products', []))}",
                f"Mitigations: {', '.join(result.get('recommended_mitigations', []))}"
            ]
        }
        log_action(db, req.correlation_id, user["id"], user["role"], "summarize_investigation", "doc_current", backend_name, "success")
        return res
    except LLMGatewayError as e:
        raise _ai_failure(db, user, req.correlation_id, "summarize_investigation", backend_name, e)
    except Exception as e:
        raise _ai_failure(db, user, req.correlation_id, "summarize_investigation", backend_name, e)

@app.post("/api/v1/investigation/decision")
def final_decision(req: DecisionRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    # Final step in the workflow where investigator makes a decision
    log_action(db, req.correlation_id, user["id"], user["role"], "final_decision", "doc_current", "none", "success", {"decision": req.decision, "notes": req.notes})
    return {"message": "Decision recorded"}

@app.post("/api/v1/pocs/find")
async def find_pocs_endpoint(
    req: PoCFindRequest,
    user: dict = Depends(get_investigator_user),
    db: Session = Depends(get_db),
):
    cve_id = req.cve_id.strip().upper()
    team2_url = os.getenv("TEAM2_API_URL", "http://localhost:8000")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(f"{team2_url}/api/v1/pocs/find", json=req.model_dump())
            if resp.status_code == 200:
                log_action(db, "poc_query", user["id"], user["role"], "poc_find", cve_id, "retrieval", "success")
                return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception:
        pass

    try:
        from threat_retrieval_engine.poc_intelligence import get_poc_finder
        finder = get_poc_finder()
        res = await finder.find_pocs(
            cve_id=cve_id,
            max_results=req.max_results,
            sources=req.sources,
            min_confidence=req.min_confidence,
        )
        log_action(db, "poc_query", user["id"], user["role"], "poc_find", cve_id, "local_engine", "success")
        return JSONResponse(status_code=200, content=res.model_dump())
    except ValueError as val_err:
        raise HTTPException(status_code=422, detail=str(val_err))
    except Exception as exc:
        ref = _new_error_reference()
        _server_log.error(f"[error ref {ref}] Failed to query PoC service: {exc}", exc_info=True)
        raise HTTPException(status_code=502, detail=f"Failed to query PoC service. Reference: {ref}")


# --- Network sensor (Task 5.0) ---
NETWORK_SENSOR_NOT_INSTALLED = ("The network sensor is not installed on this server. "
                                "Install it with: pip install -r requirements-network-sensor.txt")


def _network_sensor():
    """The network sensor (network_sensor/ folder), loaded on first use. If its packages
    (scikit-learn etc.) are not installed, the rest of the app keeps working and only
    the network sensor answers 'not installed'."""
    try:
        from network_sensor import service
        return service
    except ImportError as e:
        _server_log.error(f"The network sensor could not be loaded: {e}")
        return None


@app.get("/api/v1/network/status")
def network_sensor_status(user: dict = Depends(get_investigator_user)):
    """Is the network sensor trained, and how did it score in its last evaluation?"""
    service = _network_sensor()
    if service is None:
        return {"ready": False, "message": NETWORK_SENSOR_NOT_INSTALLED}
    return {**service.sensor.status(), "max_file_mb": MAX_NETWORK_FILE_BYTES // (1024 * 1024),
            "file_types": sorted(NETWORK_FILE_EXTENSIONS)}


def _network_file_request(file: UploadFile, user: dict, db: Session, correlation_id: str, action: str, work):
    """
    Shared by the scan and the live replay: read the uploaded file of connection
    records, apply the limits, then run work(service, connections, details).
    Every refusal goes in the audit log with the file's name, size and fingerprint.
    Returns (what work returned, details).
    """
    filename = _safe_filename(file.filename)
    content = file.file.read(MAX_NETWORK_FILE_BYTES + 1)
    details = {"filename": filename, "file_bytes": len(content), "file_sha256": _sha256(content)}

    def refuse(status: int, reason: str):
        log_action(db, correlation_id, user["id"], user["role"], action, "network_file", "none", "failure",
                   {**details, "reason": reason[:256]})
        raise HTTPException(status_code=status, detail=reason)

    if len(content) > MAX_NETWORK_FILE_BYTES:
        refuse(413, f"File too large (limit {MAX_NETWORK_FILE_BYTES // (1024 * 1024)} MB). Split the file.")
    if file_extension(filename) not in NETWORK_FILE_EXTENSIONS:
        refuse(415, f"Files of type '{file_extension(filename) or 'unknown'}' can't be scanned. "
                    f"Accepted formats: {', '.join(sorted(NETWORK_FILE_EXTENSIONS))}.")
    service = _network_sensor()
    if service is None:
        refuse(503, NETWORK_SENSOR_NOT_INSTALLED)
    try:
        return work(service, service.read_connections(content), details), details
    except service.ScanError as e:
        refuse(e.status_code, e.message)
    except Exception as e:
        # A bug or a damaged model file: the technical details go to the server log only.
        ref = _new_error_reference()
        _server_log.error(f"[error ref {ref}] Network sensor request failed: {type(e).__name__}: {e}",
                          exc_info=(type(e), e, e.__traceback__))
        refuse(500, f"The network sensor could not check this file. Reference: {ref} - "
                    "an administrator can find the details in the server log.")


@app.post(NETWORK_SCAN_PATH)
def scan_network_connections(file: UploadFile = File(...), user: dict = Depends(get_investigator_user),
                             db: Session = Depends(get_db)):
    """
    Check a file of network connection records for attacks and return the alerts,
    most serious first, each with a plain-English explanation.

    The file itself is not kept. Its name, size and fingerprint (hash) and the number
    of alerts go in the audit log - refused files too.
    (A plain "def": checking thousands of connections takes a few seconds, and FastAPI
    runs a plain function in a separate thread, so other users are not kept waiting.)
    """
    correlation_id = str(uuid.uuid4())
    result, details = _network_file_request(
        file, user, db, correlation_id, "network_scan",
        lambda service, connections, details: service.sensor.scan(connections))
    log_action(db, correlation_id, user["id"], user["role"], "network_scan", "network_file", "none", "success",
               {**details, "connections": result["connections"], "alerts": result["alerts_total"],
                "model_trained_at": result["model"]["trained_at"], "model_trained_on": result["trained_on"]})
    return {"correlation_id": correlation_id, "filename": details["filename"], **result}


@app.post(NETWORK_ALERTS_CSV_PATH)
def download_network_alerts(file: UploadFile = File(...), user: dict = Depends(get_investigator_user),
                            db: Session = Depends(get_db)):
    """
    EVERY alert in a file of connection records, as a CSV table (for Excel). The dashboard
    shows only the most serious alerts of each kind; for all of them, the browser sends the
    same file again and this checks it again. The file is still not kept. The download goes
    in the audit log like a scan.
    """
    correlation_id = str(uuid.uuid4())
    (text, facts), details = _network_file_request(
        file, user, db, correlation_id, "network_alerts_download",
        lambda service, connections, details: service.sensor.alerts_csv(connections))
    log_action(db, correlation_id, user["id"], user["role"], "network_alerts_download", "network_file", "none",
               "success", {**details, **facts})
    # The download's name: "alerts-" and the scanned file's name, in plain letters only.
    stem = "".join(c if (c.isascii() and c.isalnum()) or c in "._-" else "_"
                   for c in Path(details["filename"]).stem)[:60] or "file"
    return Response(content=text.encode("utf-8"), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="alerts-{stem}.csv"'})


# Live mode ("real-time"): the server replays a recorded file as if its connections were
# arriving now, and the dashboard asks about once a second for what has arrived since.
# See network_sensor/live.py. The start and the end of each replay go in the audit log.
@app.post(NETWORK_LIVE_START_PATH)
def start_network_live_replay(file: UploadFile = File(...), speed: int = 100,
                              user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    """Start replaying a file at `speed` connections per second (10, 100 or 1000)."""
    def begin(service, connections, details):
        service.sensor.model(service.dataset_of(connections))   # refuse now if that sensor is not trained
        return service.live.start(user["id"], connections, speed, details)

    (session, replaced), details = _network_file_request(
        file, user, db, str(uuid.uuid4()), "network_live_start", begin)
    if replaced:
        log_action(db, replaced["session_id"], user["id"], user["role"], "network_live_end", "network_file",
                   "none", "success", replaced)
    log_action(db, session.id, user["id"], user["role"], "network_live_start", "network_file", "none", "success",
               {**details, "connections": len(session.connections), "speed": session.speed})
    return {"session_id": session.id, "filename": details["filename"],
            "total": len(session.connections), "speed": session.speed,
            "dataset": session.dataset, "dataset_title": session.dataset_title}


@app.post("/api/v1/network/live/{session_id}/next")
def next_network_live_step(session_id: str, user: dict = Depends(get_investigator_user),
                           db: Session = Depends(get_db)):
    """Check the connections that have 'arrived' since the last call. Only the user who
    started a replay can use it; for anyone else it does not exist (404)."""
    service = _network_sensor()
    if service is None:
        raise HTTPException(status_code=503, detail=NETWORK_SENSOR_NOT_INSTALLED)
    try:
        result = service.live.step(session_id, user["id"], service.sensor.model)
    except service.ScanError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    if "summary" in result:
        log_action(db, session_id, user["id"], user["role"], "network_live_end", "network_file", "none",
                   "success", result["summary"])
    return result


@app.post("/api/v1/network/live/{session_id}/stop")
def stop_network_live_replay(session_id: str, user: dict = Depends(get_investigator_user),
                             db: Session = Depends(get_db)):
    service = _network_sensor()
    if service is None:
        raise HTTPException(status_code=503, detail=NETWORK_SENSOR_NOT_INSTALLED)
    try:
        summary = service.live.stop(session_id, user["id"])
    except service.ScanError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    log_action(db, session_id, user["id"], user["role"], "network_live_end", "network_file", "none",
               "success", summary)
    return summary


# Serve frontend static files
_APP_ROOT = Path(__file__).resolve().parent.parent.parent   # security_platform/ (in Docker: /app)
_FRONTEND_DIR = _APP_ROOT / "frontend"


def set_file_types():
    """Label the dashboard files correctly whatever the computer says (Windows often says .js = text/plain)."""
    mimetypes.add_type("text/html", ".html")
    mimetypes.add_type("text/css", ".css")
    mimetypes.add_type("text/javascript", ".js")


set_file_types()
app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
