from dataclasses import dataclass
from typing import Any, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

import secrets

NONCE_SIZE = 16
KEY_LENGTH = 32
HMAC_KEY_LENGTH = 16
CHACHA_NONCE_SIZE = 12


def XOR(a:bytes,b:bytes) -> bytes:
    return bytes(
        [a^b for a,b in zip(a,b)]
    )

@dataclass
class xy:
    name : str


xy(name="lukas")

@dataclass
class CryptoHandshakeContainer:

    hello_message : Any = None
    key_share : X25519PrivateKey = None
    nonce: bytes = None
    encryption_key: bytes = None
    integrity_key : bytes = None
    
    def key_share_init(self) -> Tuple[X25519PublicKey,bytes]:
        self.key_share = X25519PrivateKey.generate()
        self.nonce = secrets.token_bytes(16)
        return self.key_share.public_key(),self.nonce

    def finish_key_share(self,other_public_share : X25519PublicKey,other_nonce: bytes):
        shared_secret = self.key_share.exchange(
            other_public_share
        )

        # acts like a one time pad, enough if one nonce is truly random
        combined_nonce = XOR(self.nonce,other_nonce)

        keys = HKDF(
            algorithm=SHA256(),
            length=KEY_LENGTH + HMAC_KEY_LENGTH,
            salt=combined_nonce,
            backend=default_backend(),
            info=None
        ).derive(shared_secret)

        self.encryption_key = keys[:KEY_LENGTH]
        self.integrity_key = keys[KEY_LENGTH:]

    def validate_key_share(self,public_key : rsa.RSAPublicKey,message: bytes,signature : bytes) -> bool:
        try:
            public_key.verify(
                algorithm=SHA256(),
                signature=signature,
                data=message,
                padding=padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                )
            )
        except InvalidSignature:
            return False
        return True

    def create_key_share_signature(self,private_key : rsa.RSAPrivateKey) -> bytes:
        return private_key.sign(
                data=self.key_share.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
                algorithm=SHA256(),
                padding=padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                )
            ) 

    def check_integrity(self,message,target) -> bool:
        instance = HMAC(
            key=self.integrity_key,
            algorithm=SHA256(),
            backend=default_backend,
        )

        instance.update(message)
        
        try:
            instance.verify(target)
        except InvalidSignature:
            return False
        return True
    
    def create_integrity(self,message) -> bytes:
        instance = HMAC(
            key=self.integrity_key,
            algorithm=SHA256(),
            backend=default_backend,
        )

        instance.update(message)
        return instance.finalize()

    def encrypt(self,data : bytes) -> Tuple[bytes,bytes]:
        instance = ChaCha20Poly1305(self.encryption_key)
        nonce = secrets.token_bytes(12)

        return nonce,instance.encrypt(
            nonce=nonce,data=data,associated_data=None
        )

    def decrypt(self,nonce : bytes,data : bytes) -> bytes:
        instance = ChaCha20Poly1305(self.encryption_key)

        return instance.decrypt(
            nonce=nonce,data=data,associated_data=None
        )
        