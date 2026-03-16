from dpc.crypto.keys import generate_keypair
from dpc.crypto.signatures import sign_payload, verify_signature

def test_sign_and_verify() -> None:
    private_key, public_key = generate_keypair()
    payload = b"hello"
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, payload, signature)

def test_verify_signature_unknown_public_key() -> None:
    _, known_public_key = generate_keypair()
    payload = b"hello"
    signature = sign_payload(generate_keypair()[0], payload)
    unknown_public_key = b"\x00" * len(known_public_key)
    assert not verify_signature(unknown_public_key, payload, signature)
