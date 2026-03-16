"""Cryptographic helpers for Ed25519 signatures.

Primary backend: `cryptography` package (cross-platform and recommended).
Fallback backend: OpenSSL CLI when `cryptography` is unavailable.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def _load_cryptography() -> tuple[object, object] | None:
    """Load cryptography Ed25519 classes lazily.

    Returns:
        Tuple of (Ed25519PrivateKey, Ed25519PublicKey) classes, or None if unavailable.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        return Ed25519PrivateKey, Ed25519PublicKey
    except Exception:
        return None


def _run(cmd: list[str]) -> bytes:
    """Run a shell command and return stdout bytes."""
    proc = subprocess.run(cmd, check=True, capture_output=True)
    return proc.stdout


def _ensure_openssl() -> None:
    """Raise a helpful error when OpenSSL CLI is unavailable."""
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "No Ed25519 backend available. Install Python package 'cryptography' "
            "(recommended) or install OpenSSL CLI and ensure 'openssl' is on PATH."
        ) from exc


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair and return (private_key, public_key) strings.

    - With `cryptography`: returns raw key bytes encoded as hex.
    - With OpenSSL fallback: returns PEM strings.
    """
    crypto = _load_cryptography()
    if crypto is not None:
        Ed25519PrivateKey, _ = crypto
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return private_bytes.hex(), public_bytes.hex()

    _ensure_openssl()
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        private_path = td_path / "ed25519_private.pem"
        public_path = td_path / "ed25519_public.pem"

        _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_path)])
        _run(["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)])
        return private_path.read_text(), public_path.read_text()


def sign(message: bytes, private_key: str) -> str:
    """Sign a message with Ed25519 and return signature as hex."""
    crypto = _load_cryptography()
    if crypto is not None and "BEGIN" not in private_key:
        Ed25519PrivateKey, _ = crypto
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
        return sk.sign(message).hex()

    _ensure_openssl()
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        key_path = td_path / "private.pem"
        msg_path = td_path / "msg.bin"
        sig_path = td_path / "sig.bin"

        key_path.write_text(private_key)
        msg_path.write_bytes(message)

        _run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-in",
                str(msg_path),
                "-out",
                str(sig_path),
            ]
        )
        return sig_path.read_bytes().hex()


def verify(message: bytes, signature_hex: str, public_key: str) -> bool:
    """Verify an Ed25519 signature."""
    try:
        crypto = _load_cryptography()
        if crypto is not None and "BEGIN" not in public_key:
            _, Ed25519PublicKey = crypto
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
            pk.verify(bytes.fromhex(signature_hex), message)
            return True

        _ensure_openssl()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            pub_path = td_path / "public.pem"
            msg_path = td_path / "msg.bin"
            sig_path = td_path / "sig.bin"

            pub_path.write_text(public_key)
            msg_path.write_bytes(message)
            sig_path.write_bytes(bytes.fromhex(signature_hex))

            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(pub_path),
                    "-rawin",
                    "-in",
                    str(msg_path),
                    "-sigfile",
                    str(sig_path),
                ],
                check=True,
                capture_output=True,
            )
            return True
    except Exception:
        return False
