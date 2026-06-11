"""Cryptographic utilities for DPC: Ed25519 signatures, X25519 ECDH, ChaCha20-Poly1305 AEAD."""
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
    """Generate fresh Ed25519 keypair. Returns (private_key_32_bytes, public_key_32_bytes)."""
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
    """Sign message with Ed25519 private key. Returns 64-byte signature."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(message)


def ed25519_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature. Returns True if valid, False otherwise (never raises)."""
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def ed25519_pubkey_to_hex(public_key_bytes: bytes) -> str:
    """Encode 32-byte Ed25519 public key as hex string."""
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return public_key_bytes.hex()


def hex_to_pubkey_bytes(hex_str: str) -> bytes:
    """Decode hex string to 32-byte Ed25519 public key."""
    key = bytes.fromhex(hex_str)
    if len(key) != 32:
        raise ValueError("Public key must decode to 32 bytes")
    return key


def sha256_hex(*parts: bytes) -> str:
    """Concatenate all byte parts and return SHA-256 hex digest."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def generate_nonce_hex() -> str:
    """Generate 128-bit CSPRNG nonce as hex string (32 hex chars)."""
    return secrets.token_hex(16)


def ed25519_to_x25519_private(ed25519_private_bytes: bytes) -> bytes:
    """Convert Ed25519 private key to X25519 via SHA-512 hash and clamping."""
    h = hashlib.sha512(ed25519_private_bytes).digest()
    scalar = bytearray(h[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


def ed25519_to_x25519_public(ed25519_public_bytes: bytes) -> bytes:
    """Convert Ed25519 public key to X25519 via Montgomery ladder equivalence."""
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
    """
    Derive 32-byte session key via X25519 ECDH + HKDF-SHA256.
    1. Convert both keys to X25519
    2. Perform ECDH exchange
    3. HKDF-expand with nonce as salt, "DPC-session" as info
    """
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
    """Encrypt plaintext with ChaCha20-Poly1305. Returns ciphertext with 16-byte auth tag appended."""
    return ChaCha20Poly1305(key).encrypt(nonce_12, plaintext, None)


def chacha20_poly1305_decrypt(key: bytes, nonce_12: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Decrypt and authenticate ciphertext. Raises ValueError if authentication fails."""
    try:
        return ChaCha20Poly1305(key).decrypt(nonce_12, ciphertext_with_tag, None)
    except Exception as exc:
        raise ValueError("BLE session authentication failed") from exc
