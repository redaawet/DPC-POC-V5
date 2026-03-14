"""Cryptographic helpers based on Ed25519 via OpenSSL CLI.

This keeps the project dependency-free in restricted environments where the
`cryptography` package is unavailable.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def _run(cmd: list[str]) -> bytes:
    proc = subprocess.run(cmd, check=True, capture_output=True)
    return proc.stdout


def generate_keypair() -> tuple[str, str]:
    """Generate Ed25519 keypair and return PEM strings (private_pem, public_pem)."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        private_path = td_path / "ed25519_private.pem"
        public_path = td_path / "ed25519_public.pem"

        _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_path)])
        _run(["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)])

        return private_path.read_text(), public_path.read_text()


def sign(message: bytes, private_key_pem: str) -> str:
    """Sign a message with Ed25519 and return signature as hex."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        key_path = td_path / "private.pem"
        msg_path = td_path / "msg.bin"
        sig_path = td_path / "sig.bin"

        key_path.write_text(private_key_pem)
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


def verify(message: bytes, signature_hex: str, public_key_pem: str) -> bool:
    """Verify an Ed25519 signature."""
    try:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            pub_path = td_path / "public.pem"
            msg_path = td_path / "msg.bin"
            sig_path = td_path / "sig.bin"

            pub_path.write_text(public_key_pem)
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
