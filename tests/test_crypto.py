import pytest

pytest.importorskip("cryptography")

from crypto.signatures import generate_keypair, sign_message, verify_signature


def test_sign_and_verify_round_trip() -> None:
    sk, pk = generate_keypair()
    message = b"server-side-ed25519"

    signature = sign_message(sk, message)

    assert verify_signature(pk, message, signature) is True


def test_verify_fails_with_different_public_key() -> None:
    sk, _pk = generate_keypair()
    _other_sk, other_pk = generate_keypair()
    message = b"server-side-ed25519"

    signature = sign_message(sk, message)

    assert verify_signature(other_pk, message, signature) is False
