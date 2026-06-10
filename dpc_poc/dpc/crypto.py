from __future__ import annotations

import hashlib
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


P = 2**255 - 19


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def ed25519_sign(private_key_bytes: bytes, message: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(message)


def ed25519_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ed25519_pubkey_to_hex(public_key_bytes: bytes) -> str:
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return public_key_bytes.hex()


def hex_to_pubkey_bytes(hex_str: str) -> bytes:
    key = bytes.fromhex(hex_str)
    if len(key) != 32:
        raise ValueError("Public key must decode to 32 bytes")
    return key


def sha256_hex(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def generate_nonce_hex() -> str:
    return secrets.token_hex(16)


def ed25519_to_x25519_private(ed25519_private_bytes: bytes) -> bytes:
    h = hashlib.sha512(ed25519_private_bytes).digest()
    scalar = bytearray(h[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


def ed25519_to_x25519_public(ed25519_public_bytes: bytes) -> bytes:
    if len(ed25519_public_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    y_bytes = bytearray(ed25519_public_bytes)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        raise ValueError("Invalid Ed25519 public key")
    u = ((1 + y) * pow(1 - y, -1, P)) % P
    return u.to_bytes(32, "little")


def derive_session_key(
    my_ed25519_private: bytes,
    peer_ed25519_public: bytes,
    nonce: bytes,
) -> bytes:
    x_private = x25519.X25519PrivateKey.from_private_bytes(
        ed25519_to_x25519_private(my_ed25519_private)
    )
    x_public = x25519.X25519PublicKey.from_public_bytes(
        ed25519_to_x25519_public(peer_ed25519_public)
    )
    shared_secret = x_private.exchange(x_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=b"DPC-session",
    ).derive(shared_secret)


def chacha20_poly1305_encrypt(key: bytes, nonce_12: bytes, plaintext: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce_12, plaintext, None)


def chacha20_poly1305_decrypt(key: bytes, nonce_12: bytes, ciphertext_with_tag: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce_12, ciphertext_with_tag, None)
    except Exception as exc:
        raise ValueError("BLE session authentication failed") from exc
