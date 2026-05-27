import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
PKI_DIR = ARTIFACTS_DIR / "pki"

AAA_PORT = int(os.getenv("AAA_PORT", "8401"))
CA_PORT = int(os.getenv("CA_PORT", "8402"))
CM_PORT = int(os.getenv("CM_PORT", "8403"))
KM_PORT = int(os.getenv("KM_PORT", "8404"))
RM_PORT = int(os.getenv("RM_PORT", "8405"))
FRONTEND_PORT = int(os.getenv("FRONTEND_PORT", "8080"))

AAA_URL = f"http://127.0.0.1:{AAA_PORT}"
CA_URL = f"http://127.0.0.1:{CA_PORT}"
CM_URL = f"http://127.0.0.1:{CM_PORT}"
KM_URL = f"http://127.0.0.1:{KM_PORT}"
RM_URL = f"http://127.0.0.1:{RM_PORT}"
FRONTEND_URL = f"http://127.0.0.1:{FRONTEND_PORT}"

DEMO_ROOT_CERT_PATH = PKI_DIR / "root_ca" / "root_ca_cert.pem"
DEMO_ROOT_KEY_PATH = PKI_DIR / "root_ca" / "root_ca_key.pem"
DEMO_INTERMEDIATE_CERT_PATH = PKI_DIR / "intermediate_ca" / "intermediate_ca_cert.pem"
DEMO_INTERMEDIATE_KEY_PATH = PKI_DIR / "intermediate_ca" / "intermediate_ca_key.pem"
DEMO_CA_BUNDLE_PATH = PKI_DIR / "ca_bundle.pem"

AAA_TLS_CERT = PKI_DIR / "services" / "aaa_tls_fullchain.pem"
AAA_TLS_KEY = PKI_DIR / "services" / "aaa_tls_key.pem"
CA_TLS_CERT = PKI_DIR / "services" / "ca_tls_fullchain.pem"
CA_TLS_KEY = PKI_DIR / "services" / "ca_tls_key.pem"
CM_TLS_CERT = PKI_DIR / "services" / "cm_tls_fullchain.pem"
CM_TLS_KEY = PKI_DIR / "services" / "cm_tls_key.pem"
KM_TLS_CERT = PKI_DIR / "services" / "km_tls_fullchain.pem"
KM_TLS_KEY = PKI_DIR / "services" / "km_tls_key.pem"
RM_TLS_CERT = PKI_DIR / "services" / "rm_tls_fullchain.pem"
RM_TLS_KEY = PKI_DIR / "services" / "rm_tls_key.pem"
FRONTEND_TLS_CERT = PKI_DIR / "services" / "frontend_tls_fullchain.pem"
FRONTEND_TLS_KEY = PKI_DIR / "services" / "frontend_tls_key.pem"

KM_APPLICATION_CERT = PKI_DIR / "services" / "km_app_cert.pem"
KM_APPLICATION_KEY = PKI_DIR / "services" / "km_app_key.pem"
CM_APPLICATION_CERT = PKI_DIR / "services" / "cm_app_cert.pem"
CM_APPLICATION_KEY = PKI_DIR / "services" / "cm_app_key.pem"

TLS_VERIFY_PATH = str(DEMO_ROOT_CERT_PATH)

SERVICE_IDENTITIES = {
    "km": "km.demo.internal",
    "cm": "cm.demo.internal",
    "aaa": "aaa.demo.internal",
    "ca": "ca.demo.internal",
    "rm": "rm.demo.internal",
    "frontend": "frontend.demo.internal",
}

DEMO_USERS_FILE = REPO_ROOT / "services" / "aaa_service" / "data" / "users.json"
AAA_STATE_FILE = REPO_ROOT / "services" / "aaa_service" / "data" / "aaa_state.json"
CA_STATE_FILE = REPO_ROOT / "services" / "ca_service" / "data" / "ca_state.json"
CM_STATE_FILE = REPO_ROOT / "services" / "cm_service" / "data" / "cm_state.json"
KM_STATE_FILE = REPO_ROOT / "services" / "km_service" / "data" / "km_state.json"
RM_STATE_FILE = REPO_ROOT / "services" / "rm_service" / "data" / "rm_state.json"
RM_RESOURCE_DIR = REPO_ROOT / "services" / "rm_service" / "data" / "resources"

JWT_SECRET = "demo-jwt-secret-change-for-production"
JWT_ALGORITHM = "HS256"

SESSION_VALIDITY_HOURS = 8
TRANSACTION_VALIDITY_MINUTES = 15

DEFAULT_APPROVAL_TTL_SECONDS = 120
REQUEST_TIMEOUT_SECONDS = 25

DEMO_USERS = [
    {
        "username": "alice",
        "password": "alice123",
        "email": "alice@example.com",
        "role": "data_owner",
        "display_name": "Alice (Legitimate DO)",
    },
    {
        "username": "bob",
        "password": "bob123",
        "email": "bob@example.com",
        "role": "data_requester",
        "display_name": "Bob (Legitimate DR)",
    },
    {
        "username": "mallory",
        "password": "mallory123",
        "email": "mallory@example.com",
        "role": "data_requester",
        "display_name": "Mallory (Malicious Requester)",
    },
    {
        "username": "dt",
        "password": "dt123",
        "email": "dt@example.com",
        "role": "data_trust_operator",
        "display_name": "DT (Malicious Internal Adversary)",
    },
]

DEFAULT_CONSENT_POLICY = {
    "allowed_requesters": ["bob@example.com"],
    "purpose": "demo research evaluation",
    "consent_version": "v1",
}
