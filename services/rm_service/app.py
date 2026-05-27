import datetime as dt
import json
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from common.config import RM_RESOURCE_DIR, RM_STATE_FILE, AAA_URL, CM_URL, KM_URL
from common.http_client import request_json
from common.logging_utils import configure_logging
from common.models import SecureDownloadRequest
from common.security.certificate_utils import CertificateUtils
from common.security.demo_ca_builder import DemoCABuilder
from common.service_state import append_event, default_state
from common.storage import JsonStore

logger = configure_logging("rm_service")
app = FastAPI(title="Demo RM Service", version="1.0.0")
utils = CertificateUtils()
DemoCABuilder().ensure_demo_pki()
store = JsonStore(RM_STATE_FILE, lambda: {
    **default_state(),
    "resources": {},
    "download_log": [],
})

def validate_access_token(access_token: str):
    response = request_json("POST", f"{AAA_URL}/api/v1/validate-token", json_body={"access_token": access_token})
    return response["payload"]

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "rm"}

@app.get("/api/v1/demo/events")
def events():
    return store.read().get("events", [])[-50:]

@app.get("/api/v1/resources")
def list_resources():
    return list(store.read().get("resources", {}).values())

@app.get("/api/v1/resources/{resource_id}")
def get_resource(resource_id: str):
    resource = store.read().get("resources", {}).get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return resource

@app.get("/api/v1/resources/{resource_id}/encrypted-key")
def get_encrypted_key(resource_id: str):
    resource = store.read().get("resources", {}).get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return {
        "resource_id": resource_id,
        "encrypted_data_key_b64": resource["encrypted_data_key_b64"],
    }


@app.get("/api/v1/resources/{resource_id}/encrypted-resource")
def get_encrypted_resource(resource_id: str):
    resource = store.read().get("resources", {}).get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return {
        "resource_id": resource_id,
        "resource_name": resource["resource_name"],
        "owner_identity": resource["owner_identity"],
        "encrypted_resource_b64": utils.b64encode(Path(resource["resource_blob_path"]).read_bytes()),
    }

@app.post("/api/v1/upload")
async def upload(
    access_token: str = Form(...),
    owner_identity: str = Form(...),
    resource_name: str = Form(...),
    media_type: str = Form(...),
    encrypted_resource_file: UploadFile = File(...),
    encrypted_data_key_b64: str = Form(...),
):
    try:
        token_payload = validate_access_token(access_token)
        if token_payload["sub"] != owner_identity:
            raise ValueError("Access token identity mismatch for upload")
        resource_id = f"res-{uuid.uuid4().hex[:12]}"
        encrypted_bytes = await encrypted_resource_file.read()
        storage_path = RM_RESOURCE_DIR / f"{resource_id}_{encrypted_resource_file.filename}"
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        storage_path.write_bytes(encrypted_bytes)
        resource_record = {
            "resource_id": resource_id,
            "resource_name": resource_name,
            "stored_file_name": encrypted_resource_file.filename,
            "owner_identity": owner_identity,
            "media_type": media_type,
            "resource_blob_path": str(storage_path),
            "encrypted_data_key_b64": encrypted_data_key_b64,
            "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        data = store.read()
        data.setdefault("resources", {})[resource_id] = resource_record
        append_event(data, "rm", "upload", "success", {"resource_id": resource_id, "owner_identity": owner_identity, "file_name": encrypted_resource_file.filename})
        store.write(data)
        return resource_record
    except Exception as exc:
        data = store.read()
        append_event(data, "rm", "upload", "failure", {"error": str(exc)})
        store.write(data)
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/v1/download")
def download(request: SecureDownloadRequest):
    try:
        data = store.read()
        resource = data.get("resources", {}).get(request.resource_id)
        if resource is None:
            raise ValueError("resource not found")
        cm_response = request_json("POST", f"{CM_URL}/api/v1/evaluate-consent", json_body={
            "resource_id": request.resource_id,
            "transaction_certificate_pem": request.transaction_certificate_pem,
        })
        km_response = request_json("POST", f"{KM_URL}/api/v1/release-data-key", json_body={
            "resource_id": request.resource_id,
            "transaction_certificate_pem": request.transaction_certificate_pem,
            "cm_approval_payload": cm_response["approval_payload"],
            "cm_signature_b64": cm_response["cm_signature_b64"],
            "cm_certificate_pem": cm_response["cm_certificate_pem"],
            "encrypted_data_key_b64": resource["encrypted_data_key_b64"],
        })
        encrypted_resource_b64 = utils.b64encode(Path(resource["resource_blob_path"]).read_bytes())
        result = {
            "resource_id": request.resource_id,
            "resource_name": resource["resource_name"],
            "owner_identity": resource["owner_identity"],
            "encrypted_resource_b64": encrypted_resource_b64,
            "re_encrypted_data_key_b64": km_response["re_encrypted_data_key_b64"],
            "cm_approval_payload": cm_response["approval_payload"],
            "cm_signature_b64": cm_response["cm_signature_b64"],
            "cm_certificate_pem": cm_response["cm_certificate_pem"],
        }
        data.setdefault("download_log", []).append({
            "requested_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "resource_id": request.resource_id,
            "requester_identity": km_response["requester_identity"],
            "result": result,
        })
        data["download_log"] = data["download_log"][-50:]
        append_event(data, "rm", "download", "success", {"resource_id": request.resource_id, "requester_identity": km_response["requester_identity"]})
        store.write(data)
        return result
    except Exception as exc:
        data = store.read()
        append_event(data, "rm", "download", "failure", {"resource_id": request.resource_id, "error": str(exc)})
        store.write(data)
        raise HTTPException(status_code=400, detail=str(exc))
