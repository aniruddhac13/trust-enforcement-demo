import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SymmetricCryptography:
    def __init__(self, key: bytes = None):
        self._key = key or AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._key)

    def get_key(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        nonce = ciphertext[:12]
        body = ciphertext[12:]
        return self._aesgcm.decrypt(nonce, body, aad)
