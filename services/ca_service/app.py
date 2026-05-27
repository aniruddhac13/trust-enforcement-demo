import base64
import datetime as dt
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from common.config import (
    CA_STATE_FILE,
    DEMO_INTERMEDIATE_CERT_PATH,
    DEMO_INTERMEDIATE_KEY_PATH,
    DEMO_ROOT_CERT_PATH,
    SERVICE_IDENTITIES,
    SESSION_VALIDITY_HOURS,
    TRANSACTION_VALIDITY_MINUTES,
)
from common.logging_utils import configure_logging
from common.models import IssueSessionCertificateRequest, IssueTransactionCertificateRequest, RevokeCertificateRequest
from common.security.asymmetric_cryptography import AsymmetricCryptography
from common.security.certificate_utils import CertificateUtils, CERT_ROLE_OID
from common.security.demo_ca_builder import DemoCABuilder
from common.service_state import default_state, append_event
from common.storage import JsonStore

logger = configure_logging("ca_service")
app = FastAPI(title="Demo CA Service", version="1.0.0")
utils = CertificateUtils()
builder = DemoCABuilder()
builder.ensure_demo_pki()
store = JsonStore(CA_STATE_FILE, lambda: {
    **default_state(),
    "issued_certificates": {},
    "revoked_serials": {},
    "captured_transaction_requests": [],
})

def load_revoked_serials():
    return set(store.read().get("revoked_serials", {}).keys())

def persist_state(mutator):
    data = store.read()
    updated = mutator(data)
    store.write(updated)
    return updated

def issue_certificate_from_csr(csr_pem: str, cert_type: str, validity_seconds: int):
    csr = utils.validate_csr(csr_pem, cert_type)
    intermediate_key = AsymmetricCryptography.load_private_key(DEMO_INTERMEDIATE_KEY_PATH.read_text(encoding="utf-8"))
    intermediate_cert = utils.load_pem_certificate(DEMO_INTERMEDIATE_CERT_PATH.read_text(encoding="utf-8"))
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(seconds=validity_seconds))
        .add_extension(x509.SubjectAlternativeName(csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)
        .add_extension(x509.UnrecognizedExtension(CERT_ROLE_OID, cert_type.encode("utf-8")), critical=False)
    )
    cert = builder.sign(private_key=intermediate_key, algorithm=hashes.SHA256(), backend=default_backend())
    cert_pem = utils.serialize_cert_pem(cert)
    return cert_pem, cert

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "ca"}

@app.get("/api/v1/ca-chain")
def ca_chain():
    return {
        "root_certificate_pem": DEMO_ROOT_CERT_PATH.read_text(encoding="utf-8"),
        "intermediate_certificate_pem": DEMO_INTERMEDIATE_CERT_PATH.read_text(encoding="utf-8"),
    }

@app.get("/api/v1/revocations/{serial_hex}")
def is_revoked(serial_hex: str):
    data = store.read()
    revoked = data.get("revoked_serials", {}).get(serial_hex.lower())
    return {"serial_hex": serial_hex.lower(), "revoked": revoked is not None, "details": revoked}

@app.get("/api/v1/demo/events")
def events():
    return store.read().get("events", [])[-50:]

@app.post("/api/v1/issue-session-certificate")
def issue_session_certificate(request: IssueSessionCertificateRequest):
    try:
        csr = utils.validate_csr(request.csr_pem, "client_session")
        san_identity = utils.normalize_email_address(csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.RFC822Name)[0])
        if san_identity != utils.normalize_email_address(request.verified_identity):
            raise ValueError("Verified identity does not match session CSR SAN")
        cert_pem, cert = issue_certificate_from_csr(request.csr_pem, "client_session", SESSION_VALIDITY_HOURS * 3600)

        def mut(data):
            serial_hex = format(cert.serial_number, "x")
            data["issued_certificates"][serial_hex] = {
                "cert_type": "client_session",
                "identity": san_identity,
                "issued_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "certificate_pem": cert_pem,
            }
            append_event(data, "ca", "issue_session_certificate", "success", {"identity": san_identity, "serial_hex": serial_hex})
            return data
        persist_state(mut)
        return {"certificate_pem": cert_pem, "serial_hex": format(cert.serial_number, "x")}
    except Exception as exc:
        persist_state(lambda data: append_event(data, "ca", "issue_session_certificate", "failure", {"error": str(exc)}) or data)
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/v1/issue-transaction-certificate")
def issue_transaction_certificate(request: IssueTransactionCertificateRequest):
    try:
        revoked_serials = load_revoked_serials()
        utils.validate_certificate(request.session_certificate_pem, "client_session", revoked_serials=revoked_serials)
        session_identity = utils.extract_identity(request.session_certificate_pem, "client_session")
        session_cert = utils.load_pem_certificate(request.session_certificate_pem)
        tx_csr = utils.validate_csr(request.transaction_csr_pem, "client_transaction")
        tx_identity = utils.normalize_email_address(tx_csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.RFC822Name)[0])
        if tx_identity != session_identity:
            raise ValueError("Transaction CSR identity does not match session certificate identity")
        tx_csr_der = tx_csr.public_bytes(serialization.Encoding.DER)
        signature = base64.b64decode(request.binding_signature_b64.encode("utf-8"))
        session_cert.public_key().verify(
            signature,
            tx_csr_der,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        cert_pem, cert = issue_certificate_from_csr(request.transaction_csr_pem, "client_transaction", TRANSACTION_VALIDITY_MINUTES * 60)

        def mut(data):
            serial_hex = format(cert.serial_number, "x")
            data["issued_certificates"][serial_hex] = {
                "cert_type": "client_transaction",
                "identity": tx_identity,
                "issued_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "certificate_pem": cert_pem,
                "session_certificate_fingerprint": utils.certificate_fingerprint_sha256(request.session_certificate_pem),
            }
            data.setdefault("captured_transaction_requests", []).append({
                "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "identity": tx_identity,
                "session_certificate_pem": request.session_certificate_pem,
                "transaction_csr_pem": request.transaction_csr_pem,
                "binding_signature_b64": request.binding_signature_b64,
                "transaction_certificate_pem": cert_pem,
            })
            data["captured_transaction_requests"] = data["captured_transaction_requests"][-50:]
            append_event(data, "ca", "issue_transaction_certificate", "success", {"identity": tx_identity, "serial_hex": serial_hex})
            return data
        persist_state(mut)
        return {"certificate_pem": cert_pem, "serial_hex": format(cert.serial_number, "x"), "identity": tx_identity}
    except Exception as exc:
        persist_state(lambda data: append_event(data, "ca", "issue_transaction_certificate", "failure", {"error": str(exc)}) or data)
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/v1/revoke-certificate")
def revoke_certificate(request: RevokeCertificateRequest):
    try:
        cert = utils.load_pem_certificate(request.certificate_pem)
        serial_hex = format(cert.serial_number, "x")
        def mut(data):
            data.setdefault("revoked_serials", {})[serial_hex] = {
                "reason": request.reason,
                "revoked_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            append_event(data, "ca", "revoke_certificate", "success", {"serial_hex": serial_hex, "reason": request.reason})
            return data
        persist_state(mut)
        return {"serial_hex": serial_hex, "revoked": True}
    except Exception as exc:
        persist_state(lambda data: append_event(data, "ca", "revoke_certificate", "failure", {"error": str(exc)}) or data)
        raise HTTPException(status_code=400, detail=str(exc))

@app.get("/api/v1/demo/latest-transaction-bundle/{identity}")
def latest_transaction_bundle(identity: str):
    normalized = utils.normalize_email_address(identity)
    items = [item for item in store.read().get("captured_transaction_requests", []) if item.get("identity") == normalized]
    if not items:
        raise HTTPException(status_code=404, detail="No captured transaction bundle found for identity")
    return items[-1]
