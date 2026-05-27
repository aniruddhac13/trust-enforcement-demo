import datetime as dt
import json

from fastapi import FastAPI, HTTPException

from common.config import KM_APPLICATION_CERT, KM_APPLICATION_KEY, KM_STATE_FILE, CA_URL, SERVICE_IDENTITIES
from common.http_client import request_json
from common.logging_utils import configure_logging
from common.models import ReleaseKeyRequest
from common.security.asymmetric_cryptography import AsymmetricCryptography
from common.security.certificate_utils import CertificateUtils
from common.security.demo_ca_builder import DemoCABuilder
from common.service_state import append_event, default_state
from common.storage import JsonStore

logger = configure_logging("km_service")
app = FastAPI(title="Demo KM Service", version="1.0.0")
utils = CertificateUtils()
DemoCABuilder().ensure_demo_pki()
store = JsonStore(KM_STATE_FILE, lambda: {
    **default_state(),
    "last_release": None,
})

def is_serial_revoked(cert_pem: str) -> bool:
    serial_hex = utils.certificate_serial_hex(cert_pem)
    result = request_json("GET", f"{CA_URL}/api/v1/revocations/{serial_hex}")
    return result["revoked"]

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "km"}

@app.get("/api/v1/certificate")
def certificate():
    cert_pem = KM_APPLICATION_CERT.read_text(encoding="utf-8")
    return {
        "km_certificate_pem": cert_pem,
        "identity": utils.extract_identity(cert_pem, "server"),
    }

@app.get("/api/v1/demo/events")
def events():
    return store.read().get("events", [])[-50:]

@app.post("/api/v1/release-data-key")
def release_data_key(request: ReleaseKeyRequest):
    try:
        if is_serial_revoked(request.transaction_certificate_pem):
            raise ValueError("Transaction certificate has already been revoked")
        utils.validate_certificate(request.transaction_certificate_pem, "client_transaction")
        utils.validate_certificate(request.cm_certificate_pem, "server", expected_identity=SERVICE_IDENTITIES["cm"])
        utils.verify_json_signature(request.cm_approval_payload, request.cm_signature_b64, request.cm_certificate_pem)

        tx_cert_fingerprint = utils.certificate_fingerprint_sha256(request.transaction_certificate_pem)
        if request.cm_approval_payload.get("transaction_certificate_fingerprint") != tx_cert_fingerprint:
            raise ValueError("Consent approval is not bound to the supplied transaction certificate")
        if request.cm_approval_payload.get("resource_id") != request.resource_id:
            raise ValueError("Consent approval resource binding mismatch")
        requester_identity = utils.extract_identity(request.transaction_certificate_pem, "client_transaction")
        if request.cm_approval_payload.get("requester_identity") != requester_identity:
            raise ValueError("Consent approval requester identity mismatch")

        km_private_key = AsymmetricCryptography.load_private_key(KM_APPLICATION_KEY.read_text(encoding="utf-8"))
        transaction_public_key = utils.load_pem_certificate(request.transaction_certificate_pem).public_key()

        encrypted_data_key = utils.b64decode(request.encrypted_data_key_b64)
        plaintext_data_key = AsymmetricCryptography(private_key=km_private_key).decrypt(encrypted_data_key)
        re_encrypted_data_key = AsymmetricCryptography(public_key=transaction_public_key).encrypt(plaintext_data_key)
        request_json("POST", f"{CA_URL}/api/v1/revoke-certificate", json_body={
            "certificate_pem": request.transaction_certificate_pem,
            "reason": "one-time transaction certificate consumed after key release",
        })
        data = store.read()
        data["last_release"] = {
            "resource_id": request.resource_id,
            "requester_identity": requester_identity,
            "tx_cert_fingerprint": tx_cert_fingerprint,
            "cm_approval_payload": request.cm_approval_payload,
            "re_encrypted_data_key_b64": utils.b64encode(re_encrypted_data_key),
        }
        append_event(data, "km", "release_data_key", "success", {
            "resource_id": request.resource_id,
            "requester_identity": requester_identity,
            "tx_cert_fingerprint": tx_cert_fingerprint,
        })
        store.write(data)
        return {
            "re_encrypted_data_key_b64": utils.b64encode(re_encrypted_data_key),
            "tx_cert_fingerprint": tx_cert_fingerprint,
            "requester_identity": requester_identity,
        }
    except Exception as exc:
        data = store.read()
        append_event(data, "km", "release_data_key", "failure", {"resource_id": request.resource_id, "error": str(exc)})
        store.write(data)
        raise HTTPException(status_code=400, detail=str(exc))
