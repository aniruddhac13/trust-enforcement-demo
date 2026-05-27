import base64
from typing import Optional, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


class AsymmetricCryptography:
    def __init__(self, private_key=None, public_key=None):
        self._private_key = private_key
        self._public_key = public_key
        if self._private_key is None and self._public_key is None:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
            self._public_key = self._private_key.public_key()
        elif self._private_key is not None and self._public_key is None:
            self._public_key = self._private_key.public_key()

    def get_private_key(self):
        return self._private_key

    def get_public_key(self):
        return self._public_key

    def serialize_private_key_pem(self) -> str:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def serialize_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._public_key.encrypt(
            plaintext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._private_key is None:
            raise ValueError("Private key required for decrypt")
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    def sign(self, payload: bytes) -> bytes:
        if self._private_key is None:
            raise ValueError("Private key required for sign")
        return self._private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )

    def verify(self, payload: bytes, signature: bytes) -> bool:
        self._public_key.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return True

    @staticmethod
    def load_private_key(private_key_pem: Union[str, bytes]):
        if isinstance(private_key_pem, str):
            private_key_pem = private_key_pem.encode("utf-8")
        return serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    @staticmethod
    def load_public_key(public_key_pem: Union[str, bytes]):
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode("utf-8")
        return serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    @staticmethod
    def b64encode(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def b64decode(data_b64: str) -> bytes:
        return base64.b64decode(data_b64.encode("utf-8"))
