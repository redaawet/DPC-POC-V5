import hashlib
import secrets

_KEY_DB: dict[str, bytes] = {}


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = secrets.token_bytes(32)
    public_key = hashlib.sha256(private_key).digest()
    _KEY_DB[public_key.hex()] = private_key
    return private_key, public_key


def public_key_bytes(public_key: bytes) -> str:
    return public_key.hex()


def private_key_for_public_hex(public_hex: str) -> bytes:
    return _KEY_DB[public_hex]
