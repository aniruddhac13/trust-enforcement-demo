import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
#!/usr/bin/env python3
import json
from pathlib import Path

from common.config import (
    AAA_STATE_FILE,
    CA_STATE_FILE,
    CM_STATE_FILE,
    KM_STATE_FILE,
    RM_STATE_FILE,
    DEMO_USERS,
    DEMO_USERS_FILE,
    RM_RESOURCE_DIR,
)
from common.security.demo_ca_builder import DemoCABuilder

def ensure_json(path: Path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(content, indent=2, sort_keys=True), encoding="utf-8")

def main():
    DemoCABuilder().ensure_demo_pki()
    DEMO_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEMO_USERS_FILE.write_text(json.dumps({"users": DEMO_USERS}, indent=2, sort_keys=True), encoding="utf-8")
    ensure_json(AAA_STATE_FILE, {"events": [], "artifacts": {}, "active_tokens": {}, "active_sessions": {}})
    ensure_json(CA_STATE_FILE, {"events": [], "artifacts": {}, "issued_certificates": {}, "revoked_serials": {}, "captured_transaction_requests": []})
    ensure_json(CM_STATE_FILE, {"events": [], "artifacts": {}, "policies": {}, "approval_log": []})
    ensure_json(KM_STATE_FILE, {"events": [], "artifacts": {}, "last_release": None})
    ensure_json(RM_STATE_FILE, {"events": [], "artifacts": {}, "resources": {}, "download_log": []})
    RM_RESOURCE_DIR.mkdir(parents=True, exist_ok=True)
    print("Demo PKI and service state initialized.")

if __name__ == "__main__":
    main()
