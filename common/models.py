from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str
    session_csr_pem: str


class IssueSessionCertificateRequest(BaseModel):
    verified_identity: str
    csr_pem: str


class IssueTransactionCertificateRequest(BaseModel):
    session_certificate_pem: str
    transaction_csr_pem: str
    binding_signature_b64: str


class RevokeCertificateRequest(BaseModel):
    certificate_pem: str
    reason: str = "unspecified"


class ConsentPolicyUpsertRequest(BaseModel):
    resource_id: str
    owner_identity: str
    allowed_requesters: List[str]
    purpose: str = "demo research evaluation"
    consent_version: str = "v1"


class EvaluateConsentRequest(BaseModel):
    resource_id: str
    transaction_certificate_pem: str


class ReleaseKeyRequest(BaseModel):
    resource_id: str
    transaction_certificate_pem: str
    cm_approval_payload: Dict
    cm_signature_b64: str
    cm_certificate_pem: str
    encrypted_data_key_b64: str


class SecureUploadMetadata(BaseModel):
    owner_identity: str
    resource_name: str
    media_type: str = "text/plain"
    allowed_requesters: List[str] = Field(default_factory=list)
    purpose: str = "demo research evaluation"
    consent_version: str = "v1"


class SecureDownloadRequest(BaseModel):
    resource_id: str
    transaction_certificate_pem: str


class EventRecord(BaseModel):
    time_utc: str
    service: str
    action: str
    status: str
    details: Dict = Field(default_factory=dict)
