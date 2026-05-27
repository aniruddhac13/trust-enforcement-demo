import datetime as dt
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from common.config import (
    DEMO_ROOT_CERT_PATH,
    DEMO_ROOT_KEY_PATH,
    DEMO_INTERMEDIATE_CERT_PATH,
    DEMO_INTERMEDIATE_KEY_PATH,
    DEMO_CA_BUNDLE_PATH,
    AAA_TLS_CERT,
    AAA_TLS_KEY,
    CA_TLS_CERT,
    CA_TLS_KEY,
    CM_TLS_CERT,
    CM_TLS_KEY,
    KM_TLS_CERT,
    KM_TLS_KEY,
    RM_TLS_CERT,
    RM_TLS_KEY,
    FRONTEND_TLS_CERT,
    FRONTEND_TLS_KEY,
    KM_APPLICATION_CERT,
    KM_APPLICATION_KEY,
    CM_APPLICATION_CERT,
    CM_APPLICATION_KEY,
)
from common.security.certificate_utils import CertificateUtils, CERT_ROLE_OID
from common.security.asymmetric_cryptography import AsymmetricCryptography


class DemoCABuilder:
    def __init__(self):
        self._utils = CertificateUtils()

    def ensure_demo_pki(self):
        if DEMO_ROOT_CERT_PATH.exists() and DEMO_INTERMEDIATE_CERT_PATH.exists() and KM_APPLICATION_CERT.exists() and CM_APPLICATION_CERT.exists() and FRONTEND_TLS_CERT.exists():
            return
        self._build_root_and_intermediate()
        self._issue_service_artifacts()

    def _build_root_and_intermediate(self):
        root_key = AsymmetricCryptography().get_private_key()
        root_subject = self._utils.build_name("Demo Root CA", organizational_unit="root")
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
        root_builder = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.UnrecognizedExtension(CERT_ROLE_OID, b"root"), critical=False)
        )
        root_cert = root_builder.sign(private_key=root_key, algorithm=hashes.SHA256(), backend=default_backend())
        DEMO_ROOT_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        DEMO_ROOT_CERT_PATH.write_text(self._utils.serialize_cert_pem(root_cert), encoding="utf-8")
        DEMO_ROOT_KEY_PATH.write_text(self._utils.pem_private_key(root_key), encoding="utf-8")

        intermediate_key = AsymmetricCryptography().get_private_key()
        intermediate_subject = self._utils.build_name("Demo Intermediate CA", organizational_unit="intermediate")
        intermediate_builder = (
            x509.CertificateBuilder()
            .subject_name(intermediate_subject)
            .issuer_name(root_cert.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.UnrecognizedExtension(CERT_ROLE_OID, b"intermediate"), critical=False)
        )
        intermediate_cert = intermediate_builder.sign(private_key=root_key, algorithm=hashes.SHA256(), backend=default_backend())
        DEMO_INTERMEDIATE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        DEMO_INTERMEDIATE_CERT_PATH.write_text(self._utils.serialize_cert_pem(intermediate_cert), encoding="utf-8")
        DEMO_INTERMEDIATE_KEY_PATH.write_text(self._utils.pem_private_key(intermediate_key), encoding="utf-8")
        DEMO_CA_BUNDLE_PATH.write_text(self._utils.serialize_cert_pem(root_cert) + self._utils.serialize_cert_pem(intermediate_cert), encoding="utf-8")

    def _issue_service_artifacts(self):
        services = [
            ("aaa_tls", AAA_TLS_CERT, AAA_TLS_KEY, ["localhost", "127.0.0.1", "aaa.demo.internal"], "server"),
            ("ca_tls", CA_TLS_CERT, CA_TLS_KEY, ["localhost", "127.0.0.1", "ca.demo.internal"], "server"),
            ("cm_tls", CM_TLS_CERT, CM_TLS_KEY, ["localhost", "127.0.0.1", "cm.demo.internal"], "server"),
            ("km_tls", KM_TLS_CERT, KM_TLS_KEY, ["localhost", "127.0.0.1", "km.demo.internal"], "server"),
            ("rm_tls", RM_TLS_CERT, RM_TLS_KEY, ["localhost", "127.0.0.1", "rm.demo.internal"], "server"),
            ("frontend_tls", FRONTEND_TLS_CERT, FRONTEND_TLS_KEY, ["localhost", "127.0.0.1", "frontend.demo.internal"], "server"),
            ("km_app", KM_APPLICATION_CERT, KM_APPLICATION_KEY, ["localhost", "km.demo.internal"], "server"),
            ("cm_app", CM_APPLICATION_CERT, CM_APPLICATION_KEY, ["localhost", "cm.demo.internal"], "server"),
        ]
        for common_name, cert_path, key_path, sans, cert_type in services:
            if cert_path.exists() and key_path.exists():
                continue
            leaf_cert_pem, key_pem = self.issue_end_entity_certificate(common_name, sans, cert_type, validity_days=365)
            fullchain_pem = leaf_cert_pem + DEMO_INTERMEDIATE_CERT_PATH.read_text(encoding="utf-8")
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            cert_path.write_text(fullchain_pem, encoding="utf-8")
            key_path.write_text(key_pem, encoding="utf-8")

    def issue_end_entity_certificate(self, common_name: str, sans: List[str], cert_type: str, validity_days: int):
        intermediate_key = AsymmetricCryptography.load_private_key(DEMO_INTERMEDIATE_KEY_PATH.read_text(encoding="utf-8"))
        intermediate_cert = self._utils.load_pem_certificate(DEMO_INTERMEDIATE_CERT_PATH.read_text(encoding="utf-8"))
        csr_result = self._utils.generate_csr(cert_type=cert_type, common_name=common_name, sans=sans)
        csr = self._utils.load_pem_csr(csr_result["csr_pem"])
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(intermediate_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=validity_days))
            .add_extension(x509.SubjectAlternativeName(csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True if cert_type == "server" else False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH] if cert_type == "server" else [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)
            .add_extension(x509.UnrecognizedExtension(CERT_ROLE_OID, cert_type.encode("utf-8")), critical=False)
        )
        cert = builder.sign(private_key=intermediate_key, algorithm=hashes.SHA256(), backend=default_backend())
        return self._utils.serialize_cert_pem(cert), csr_result["private_key_pem"]
