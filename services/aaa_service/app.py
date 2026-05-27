import datetime as dt
import json
from pathlib import Path

import jwt
from fastapi import FastAPI, HTTPException

from common.config import AAA_STATE_FILE, DEMO_USERS_FILE, JWT_ALGORITHM, JWT_SECRET, CA_URL
from common.http_client import request_json
from common.logging_utils import configure_logging
from common.models import LoginRequest, RevokeCertificateRequest
from common.security.certificate_utils import CertificateUtils
from common.security.demo_ca_builder import DemoCABuilder
from common.service_state import append_event, default_state
from common.storage import JsonStore

logger = configure_logging("aaa_service")
app = FastAPI(title="Demo AAA Service", version="1.0.0")
utils = CertificateUtils()
DemoCABuilder().ensure_demo_pki()
store = JsonStore(AAA_STATE_FILE, lambda: {**default_state(), "active_tokens": {}, "active_sessions": {}})

def load_users():
    return json.loads(DEMO_USERS_FILE.read_text(encoding="utf-8"))["users"]

def persist(mutator):
    data = store.read()
    updated = mutator(data)
    store.write(updated)
    return updated

def mint_access_token(user: dict):
    payload = {
        "sub": user["email"],
        "username": user["username"],
        "role": user["role"],
        "display_name": user["display_name"],
        "iat": int(dt.datetime.now(dt.timezone.utc).timestamp()),
        "exp": int((dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=8)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "aaa"}

@app.get("/api/v1/demo/events")
def events():
    return store.read().get("events", [])[-50:]

@app.post("/api/v1/login")
def login(request: LoginRequest):
    users = load_users()
    matching = next((user for user in users if user["username"] == request.username and user["password"] == request.password), None)
    if matching is None:
        persist(lambda data: append_event(data, "aaa", "login", "failure", {"username": request.username, "reason": "invalid credentials"}) or data)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    try:
        ca_response = request_json("POST", f"{CA_URL}/api/v1/issue-session-certificate", json_body={
            "verified_identity": matching["email"],
            "csr_pem": request.session_csr_pem,
        })
        access_token = mint_access_token(matching)
        persist(lambda data: _persist_login(data, matching, access_token, ca_response["certificate_pem"]))
        return {
            "access_token": access_token,
            "user": matching,
            "session_certificate_pem": ca_response["certificate_pem"],
        }
    except Exception as exc:
        persist(lambda data: append_event(data, "aaa", "login", "failure", {"username": request.username, "reason": str(exc)}) or data)
        raise HTTPException(status_code=400, detail=str(exc))

def _persist_login(data, user, access_token, session_certificate_pem):
    data.setdefault("active_tokens", {})[access_token] = {
        "identity": user["email"],
        "role": user["role"],
        "display_name": user["display_name"],
        "issued_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    data.setdefault("active_sessions", {})[user["email"]] = {
        "session_certificate_pem": session_certificate_pem,
        "login_time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    append_event(data, "aaa", "login", "success", {"identity": user["email"]})
    return data

@app.post("/api/v1/logout")
def logout(payload: dict):
    access_token = payload.get("access_token")
    session_certificate_pem = payload.get("session_certificate_pem")
    if not access_token or not session_certificate_pem:
        raise HTTPException(status_code=400, detail="access_token and session_certificate_pem required")
    token_payload = jwt.decode(access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    request_json("POST", f"{CA_URL}/api/v1/revoke-certificate", json_body={"certificate_pem": session_certificate_pem, "reason": "session logout"})
    persist(lambda data: _persist_logout(data, token_payload["sub"], access_token))
    return {"logout": "success"}

def _persist_logout(data, identity, access_token):
    data.get("active_tokens", {}).pop(access_token, None)
    data.get("active_sessions", {}).pop(identity, None)
    append_event(data, "aaa", "logout", "success", {"identity": identity})
    return data

@app.post("/api/v1/validate-token")
def validate_token(payload: dict):
    token = payload.get("access_token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if token not in store.read().get("active_tokens", {}):
            raise ValueError("Token is not active")
        return {"valid": True, "payload": decoded}
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.get("/api/v1/demo/active-sessions")
def active_sessions():
    return store.read().get("active_sessions", {})

@app.get("/api/v1/demo/session/{identity}")
def session_for_identity(identity: str):
    session = store.read().get("active_sessions", {}).get(identity)
    if session is None:
        raise HTTPException(status_code=404, detail="No active session found for identity")
    return session
