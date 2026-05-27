import base64
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ExtensionOID, ObjectIdentifier

from common.config import (
    DEMO_INTERMEDIATE_CERT_PATH,
    DEMO_ROOT_CERT_PATH,
)
from common.security.asymmetric_cryptography import AsymmetricCryptography

CERT_ROLE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
KNOWN_CERT_TYPES = {"root", "intermediate", "server", "client_session", "client_transaction"}


class CertificateUtils:
    def __init__(self):
        self._asym = AsymmetricCryptography()

    def normalize_dns_name(self, host: str) -> str:
        return host.strip().rstrip(".").lower()

    def normalize_email_address(self, addr: str) -> str:
        return addr.strip().lower()

    def build_name(self, common_name: str, organization: str = "Demo Prototype", organizational_unit: Optional[str] = None):
        attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
        if organizational_unit:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        return x509.Name(attributes)

    def generate_csr(
        self,
        cert_type: str,
        common_name: str,
        sans: Optional[List[str]] = None,
        organization: str = "Demo Prototype",
    ) -> Dict[str, str]:
        if cert_type not in KNOWN_CERT_TYPES:
            raise ValueError(f"Unsupported cert_type: {cert_type}")
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(self.build_name(common_name=common_name, organization=organization, organizational_unit=cert_type))
        sans = sans or []
        if cert_type in {"server"}:
            san_values = []
            for item in sans:
                item = item.strip()
                try:
                    san_values.append(x509.IPAddress(ipaddress.ip_address(item)))
                except ValueError:
                    san_values.append(x509.DNSName(self.normalize_dns_name(item)))
            builder = builder.add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        elif cert_type in {"client_session", "client_transaction"}:
            san_values = [x509.RFC822Name(self.normalize_email_address(item)) for item in sans]
            builder = builder.add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        asym = AsymmetricCryptography()
        private_key = asym.get_private_key()
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        return {
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "private_key_pem": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8"),
        }

    def load_pem_certificate(self, cert_pem: Union[str, bytes]) -> x509.Certificate:
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode("utf-8")
        return x509.load_pem_x509_certificate(cert_pem, default_backend())

    def load_pem_csr(self, csr_pem: Union[str, bytes]) -> x509.CertificateSigningRequest:
        if isinstance(csr_pem, str):
            csr_pem = csr_pem.encode("utf-8")
        return x509.load_pem_x509_csr(csr_pem, default_backend())

    def serialize_cert_pem(self, cert: x509.Certificate) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def pem_private_key(self, private_key) -> str:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def certificate_fingerprint_sha256(self, cert_pem: Union[str, bytes]) -> str:
        cert = self.load_pem_certificate(cert_pem)
        return cert.fingerprint(hashes.SHA256()).hex()

    def certificate_serial_hex(self, cert_pem: Union[str, bytes]) -> str:
        return format(self.load_pem_certificate(cert_pem).serial_number, "x")

    def public_key_pem_from_cert(self, cert_pem: Union[str, bytes]) -> str:
        cert = self.load_pem_certificate(cert_pem)
        return cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def extract_identity(self, cert_pem: Union[str, bytes], cert_type: str) -> str:
        cert = self.load_pem_certificate(cert_pem)
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        if cert_type in {"client_session", "client_transaction"}:
            emails = sans.get_values_for_type(x509.RFC822Name)
            return self.normalize_email_address(emails[0])
        if cert_type == "server":
            dns_values = sans.get_values_for_type(x509.DNSName)
            ip_values = [str(v) for v in sans.get_values_for_type(x509.IPAddress)]
            return dns_values[0] if dns_values else ip_values[0]
        return cert.subject.rfc4514_string()

    def get_cert_type(self, cert: x509.Certificate) -> str:
        try:
            return cert.extensions.get_extension_for_oid(CERT_ROLE_OID).value.value.decode("utf-8")
        except Exception:
            try:
                ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
                if ou in KNOWN_CERT_TYPES:
                    return ou
            except Exception:
                pass
        raise ValueError("Unable to determine certificate type")

    def validate_csr(self, csr_pem: Union[str, bytes], cert_type: str) -> x509.CertificateSigningRequest:
        csr = self.load_pem_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("CSR signature validation failed")
        public_key = csr.public_key()
        if not hasattr(public_key, "key_size") or public_key.key_size < 2048:
            raise ValueError("CSR public key must be RSA 2048 or stronger")
        if cert_type in {"server", "client_session", "client_transaction"}:
            csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return csr

    def _validate_chain(self, cert: x509.Certificate) -> None:
        root = self.load_pem_certificate(DEMO_ROOT_CERT_PATH.read_text(encoding="utf-8"))
        intermediate = self.load_pem_certificate(DEMO_INTERMEDIATE_CERT_PATH.read_text(encoding="utf-8"))
        cert.verify_directly_issued_by(intermediate)
        intermediate.verify_directly_issued_by(root)

    def validate_certificate(
        self,
        cert_pem: Union[str, bytes],
        cert_type: str,
        expected_identity: Optional[str] = None,
        revoked_serials: Optional[set] = None,
    ) -> Tuple[bool, x509.Certificate]:
        cert = self.load_pem_certificate(cert_pem)
        if cert.not_valid_after_utc <= dt.datetime.now(dt.timezone.utc):
            raise ValueError("Certificate expired")
        if cert.not_valid_before_utc >= dt.datetime.now(dt.timezone.utc):
            raise ValueError("Certificate not yet valid")
        self._validate_chain(cert)
        actual_cert_type = self.get_cert_type(cert)
        if cert_type != actual_cert_type:
            raise ValueError(f"Certificate type mismatch: expected {cert_type}, found {actual_cert_type}")
        if revoked_serials and format(cert.serial_number, "x") in revoked_serials:
            raise ValueError("Certificate revoked")
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if cert_type in {"root", "intermediate"}:
            if not basic_constraints.ca:
                raise ValueError("CA certificate missing ca flag")
            if not key_usage.key_cert_sign or not key_usage.crl_sign:
                raise ValueError("CA key usage invalid")
        elif cert_type == "server":
            if basic_constraints.ca:
                raise ValueError("Server certificate cannot be a CA")
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                raise ValueError("Server certificate missing serverAuth EKU")
            if expected_identity:
                normalized = self.normalize_dns_name(expected_identity)
                try:
                    identity = self.extract_identity(cert_pem, "server")
                except Exception:
                    identity = None
                sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                dns_values = [self.normalize_dns_name(v) for v in sans.get_values_for_type(x509.DNSName)]
                ip_values = [str(v) for v in sans.get_values_for_type(x509.IPAddress)]
                if normalized not in dns_values and expected_identity not in ip_values:
                    raise ValueError("Server certificate identity mismatch")
        elif cert_type in {"client_session", "client_transaction"}:
            if basic_constraints.ca:
                raise ValueError("Client certificate cannot be a CA")
            if not key_usage.digital_signature:
                raise ValueError("Client certificate must support digital signature")
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                raise ValueError("Client certificate missing clientAuth EKU")
            if expected_identity:
                identity = self.extract_identity(cert_pem, cert_type)
                if self.normalize_email_address(identity) != self.normalize_email_address(expected_identity):
                    raise ValueError("Client certificate identity mismatch")
        return True, cert

    def build_approval_payload(self, resource_id: str, requester_identity: str, transaction_certificate_pem: str, purpose: str, consent_version: str):
        return {
            "resource_id": resource_id,
            "requester_identity": self.normalize_email_address(requester_identity),
            "transaction_certificate_fingerprint": self.certificate_fingerprint_sha256(transaction_certificate_pem),
            "purpose": purpose,
            "consent_version": consent_version,
            "decision": "approved",
            "issued_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }

    def canonical_json_bytes(self, value: Dict) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_json(self, value: Dict, private_key_pem: Union[str, bytes]) -> str:
        private_key = AsymmetricCryptography.load_private_key(private_key_pem)
        signature = AsymmetricCryptography(private_key=private_key).sign(self.canonical_json_bytes(value))
        return base64.b64encode(signature).decode("utf-8")

    def verify_json_signature(self, value: Dict, signature_b64: str, cert_pem: Union[str, bytes]) -> bool:
        signature = base64.b64decode(signature_b64.encode("utf-8"))
        public_key_pem = self.public_key_pem_from_cert(cert_pem)
        public_key = AsymmetricCryptography.load_public_key(public_key_pem)
        AsymmetricCryptography(public_key=public_key).verify(self.canonical_json_bytes(value), signature)
        return True

    def hash_bytes(self, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def b64encode(self, value: bytes) -> str:
        return base64.b64encode(value).decode("utf-8")

    def b64decode(self, value: str) -> bytes:
        return base64.b64decode(value.encode("utf-8"))
