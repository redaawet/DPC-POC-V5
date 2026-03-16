import hmac
import hashlib

from dpc.crypto.keys import private_key_for_public_hex


def sign_payload(private_key: bytes, payload: bytes) -> str:
    return hmac.new(private_key, payload, hashlib.sha256).hexdigest()


def verify_signature(public_key: bytes, payload: bytes, signature_hex: str) -> bool:
    private_key = private_key_for_public_hex(public_key.hex())
    expected = sign_payload(private_key, payload)
    return hmac.compare_digest(expected, signature_hex)
