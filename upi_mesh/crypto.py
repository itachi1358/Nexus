"""Hybrid encryption, the same pattern TLS, PGP and Signal use.

RSA can only encrypt ~190 bytes with OAEP-SHA256 on a 2048-bit key, and the payment
JSON is bigger. So each packet gets a fresh AES-256 key: AES-GCM encrypts the JSON,
and RSA-OAEP encrypts just that AES key.

Wire format (before base64):
    [256 bytes RSA-encrypted AES key][12 bytes GCM IV][AES ciphertext + 16-byte tag]

AES-GCM is authenticated: flipping any bit makes decryption fail, so untrusted phones
can carry a packet but can't alter it. It does NOT prove who created the packet:
anyone with the public key can encrypt one.
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import PaymentInstruction

RSA_ENCRYPTED_KEY_BYTES = 256  # for 2048-bit RSA
GCM_IV_BYTES = 12
GCM_TAG_BYTES = 16
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

# A fresh keypair on every startup. In production the private key lives in an HSM or
# KMS (AWS KMS, HashiCorp Vault), never in the process or the source.
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = _private_key.public_key()
public_key_b64 = base64.b64encode(public_key.public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def encrypt(instruction: PaymentInstruction, server_public_key) -> str:
    """Encrypt a payment instruction with the server's public key (the sender phone's job)."""
    plaintext = instruction.model_dump_json(by_alias=True).encode()
    aes_key = AESGCM.generate_key(bit_length=256)  # one-time key for this packet
    iv = os.urandom(GCM_IV_BYTES)
    aes_ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, None)  # includes the 16-byte tag
    encrypted_key = server_public_key.encrypt(aes_key, OAEP)
    return base64.b64encode(encrypted_key + iv + aes_ciphertext).decode()


def decrypt(b64_ciphertext: str) -> PaymentInstruction:
    """Decrypt with the server's private key. Raises on bad base64, wrong key,
    tampered bytes or truncated input."""
    blob = base64.b64decode(b64_ciphertext, validate=True)
    if len(blob) < RSA_ENCRYPTED_KEY_BYTES + GCM_IV_BYTES + GCM_TAG_BYTES:
        raise ValueError("Ciphertext too short")
    iv_end = RSA_ENCRYPTED_KEY_BYTES + GCM_IV_BYTES
    aes_key = _private_key.decrypt(blob[:RSA_ENCRYPTED_KEY_BYTES], OAEP)
    plaintext = AESGCM(aes_key).decrypt(blob[RSA_ENCRYPTED_KEY_BYTES:iv_end], blob[iv_end:], None)
    return PaymentInstruction.model_validate_json(plaintext)


def hash_ciphertext(b64_ciphertext: str) -> str:
    """SHA-256 of the ciphertext bytes. THIS is the idempotency key.

    Not packet_id: intermediates can rewrite it, but can't forge a valid ciphertext.
    Not the base64 text either: decoders accept several spellings of the same bytes
    (e.g. different spare bits in the last character), so hashing the text would let
    one payment settle twice.
    """
    return hashlib.sha256(base64.b64decode(b64_ciphertext, validate=True)).hexdigest()
