"""Ed25519 signature helpers for server-side PoC flows.

This module uses the ``cryptography`` package for key generation,
signing, and verification.
"""

from __future__ import annotations

import base64
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> Tuple[str, str]:
    """Generate an Ed25519 keypair in base64 format.

    Returns:
        tuple[str, str]: A tuple containing
            (private_key_base64, public_key_base64), each encoded as
            base64 strings of the raw 32-byte key material.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_bytes).decode("ascii"), base64.b64encode(public_bytes).decode("ascii")


def sign_message(sk: str, message: bytes) -> str:
    """Sign a message with an Ed25519 private key.

    Args:
        sk: Base64-encoded Ed25519 private key (raw 32 bytes).
        message: Message bytes to sign.

    Returns:
        str: Base64-encoded signature bytes.
    """
    private_bytes = base64.b64decode(sk)
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_signature(pk: str, message: bytes, sig: str) -> bool:
    """Verify an Ed25519 signature.

    Args:
        pk: Base64-encoded Ed25519 public key (raw 32 bytes).
        message: Message bytes whose signature should be validated.
        sig: Base64-encoded Ed25519 signature.

    Returns:
        bool: ``True`` when signature verification succeeds, otherwise ``False``.
    """
    try:
        public_bytes = base64.b64decode(pk)
        signature_bytes = base64.b64decode(sig)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except (ValueError, InvalidSignature):
        return False
