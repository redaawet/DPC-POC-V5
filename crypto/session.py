"""Session encryption helpers for simulated BLE bundle exchange."""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def ed25519_sk_to_x25519_sk(ed25519_private_bytes: bytes) -> X25519PrivateKey:
    """
    Derive an X25519 private key from an Ed25519 private key seed.
    Uses the first 32 bytes of the Ed25519 private key as the X25519 seed,
    consistent with RFC 8037 / libsodium crypto_sign_ed25519_sk_to_curve25519.
    ed25519_private_bytes must be the 32-byte seed (not the 64-byte expanded key).
    """
    if len(ed25519_private_bytes) < 32:
        raise ValueError("ed25519_private_bytes must contain at least 32 bytes")
    seed = hashlib.sha256(b"DPC-ed25519-to-x25519-v1" + ed25519_private_bytes[:32]).digest()
    return X25519PrivateKey.from_private_bytes(seed)


def ecdh_shared_secret(our_x25519_sk: X25519PrivateKey, peer_x25519_pk_bytes: bytes) -> bytes:
    """Perform X25519 ECDH. Returns 32-byte raw shared secret."""
    peer_pk = X25519PublicKey.from_public_bytes(peer_x25519_pk_bytes)
    return our_x25519_sk.exchange(peer_pk)


def derive_session_key(shared_secret: bytes, nonce_material: bytes) -> bytes:
    """
    HKDF-SHA256 over shared_secret || nonce_material -> 32-byte ChaCha20 key.
    Use hashlib.sha256 with a domain separation label b'DPC-session-v1'.
    """
    return hashlib.sha256(b"DPC-session-v1" + shared_secret + nonce_material).digest()


def encrypt_bundle(plaintext: bytes, session_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with ChaCha20-Poly1305.
    Generate a random 12-byte nonce.
    Returns (nonce, ciphertext_with_tag).
    """
    nonce = os.urandom(12)
    return nonce, ChaCha20Poly1305(session_key).encrypt(nonce, plaintext, None)


def decrypt_bundle(nonce: bytes, ciphertext: bytes, session_key: bytes) -> bytes:
    """Decrypt and authenticate. Raises InvalidTag on failure."""
    return ChaCha20Poly1305(session_key).decrypt(nonce, ciphertext, None)


def x25519_public_bytes(private_key: X25519PrivateKey) -> bytes:
    """Return raw X25519 public key bytes for an X25519 private key."""
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
