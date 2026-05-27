import datetime as dt

from fastapi import FastAPI, HTTPException

from common.config import CM_APPLICATION_CERT, CM_APPLICATION_KEY, CM_STATE_FILE, CA_URL, SERVICE_IDENTITIES
from common.http_client import request_json
from common.logging_utils import configure_logging
from common.models import ConsentPolicyUpsertRequest, EvaluateConsentRequest
from common.security.certificate_utils import CertificateUtils
from common.security.demo_ca_builder import DemoCABuilder
from common.service_state import append_event, default_state
from common.storage import JsonStore

logger = configure_logging("cm_service")
app = FastAPI(title="Demo CM Service", version="1.0.0")
utils = CertificateUtils()
DemoCABuilder().ensure_demo_pki()
store = JsonStore(CM_STATE_FILE, lambda: {
    **default_state(),
    "policies": {},
    "approval_log": [],
})

def revoked_serials():
    data = request_json("GET", f"{CA_URL}/api/v1/demo/events")
    ca_state = request_json("GET", f"{CA_URL}/api/v1/ca-chain")
    return set()

def is_serial_revoked(cert_pem: str) -> bool:
    serial_hex = utils.certificate_serial_hex(cert_pem)
    result = request_json("GET", f"{CA_URL}/api/v1/revocations/{serial_hex}")
    return result["revoked"]

def validate_transaction_certificate(tx_cert_pem: str):
    if is_serial_revoked(tx_cert_pem):
        raise ValueError("Transaction certificate has been revoked")
    utils.validate_certificate(tx_cert_pem, "client_transaction")

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "cm"}

@app.get("/api/v1/demo/events")
def events():
    return store.read().get("events", [])[-50:]

@app.post("/api/v1/policies/upsert")
def upsert_policy(request: ConsentPolicyUpsertRequest):
    data = store.read()
    data.setdefault("policies", {})[request.resource_id] = request.model_dump()
    append_event(data, "cm", "upsert_policy", "success", {"resource_id": request.resource_id, "allowed_requesters": request.allowed_requesters})
    store.write(data)
    return {"stored": True, "resource_id": request.resource_id}

@app.post("/api/v1/evaluate-consent")
def evaluate_consent(request: EvaluateConsentRequest):
    try:
        validate_transaction_certificate(request.transaction_certificate_pem)
        requester_identity = utils.extract_identity(request.transaction_certificate_pem, "client_transaction")
        data = store.read()
        policy = data.get("policies", {}).get(request.resource_id)
        if policy is None:
            raise ValueError("No consent policy found for resource")
        if requester_identity not in policy.get("allowed_requesters", []):
            raise ValueError("Consent policy does not allow this requester")
        approval_payload = utils.build_approval_payload(
            resource_id=request.resource_id,
            requester_identity=requester_identity,
            transaction_certificate_pem=request.transaction_certificate_pem,
            purpose=policy.get("purpose", "demo research evaluation"),
            consent_version=policy.get("consent_version", "v1"),
        )
        signature_b64 = utils.sign_json(approval_payload, CM_APPLICATION_KEY.read_text(encoding="utf-8"))
        data.setdefault("approval_log", []).append({
            "approval_payload": approval_payload,
            "cm_signature_b64": signature_b64,
            "cm_certificate_pem": CM_APPLICATION_CERT.read_text(encoding="utf-8"),
        })
        data["approval_log"] = data["approval_log"][-50:]
        append_event(data, "cm", "evaluate_consent", "success", {
            "resource_id": request.resource_id,
            "requester_identity": requester_identity,
            "tx_cert_fingerprint": approval_payload["transaction_certificate_fingerprint"],
        })
        store.write(data)
        return {
            "approval_payload": approval_payload,
            "cm_signature_b64": signature_b64,
            "cm_certificate_pem": CM_APPLICATION_CERT.read_text(encoding="utf-8"),
        }
    except Exception as exc:
        data = store.read()
        append_event(data, "cm", "evaluate_consent", "failure", {"resource_id": request.resource_id, "error": str(exc)})
        store.write(data)
        raise HTTPException(status_code=403, detail=str(exc))

@app.get("/api/v1/demo/latest-approval/{resource_id}")
def latest_approval(resource_id: str):
    approvals = [item for item in store.read().get("approval_log", []) if item.get("approval_payload", {}).get("resource_id") == resource_id]
    if not approvals:
        raise HTTPException(status_code=404, detail="No approval found for resource")
    return approvals[-1]
