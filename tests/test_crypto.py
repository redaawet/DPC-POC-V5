from dpc.crypto.keys import generate_keypair
from dpc.crypto.signatures import sign_payload, verify_signature


def test_sign_and_verify() -> None:
    private_key, public_key = generate_keypair()
    payload = b"hello"
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, payload, signature)
