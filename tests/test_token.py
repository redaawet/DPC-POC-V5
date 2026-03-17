import pytest

pytest.importorskip("cryptography")

from crypto.signatures import generate_keypair, sign_message
from digital_token.token_model import Token


def test_token_issuance_transfer_and_chain_validation() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    owner_sk, owner_pk = generate_keypair()
    _receiver_sk, receiver_pk = generate_keypair()

    token = Token(
        token_id="tok-001",
        value=25,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())

    token.append_transfer(sender_sk=owner_sk, receiver_pk=receiver_pk)

    assert token.validate_chain(issuer_pk) is True


def test_validate_chain_fails_for_tampered_transfer() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    owner_sk, owner_pk = generate_keypair()
    _receiver_sk, receiver_pk = generate_keypair()

    token = Token(
        token_id="tok-002",
        value=10,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())

    token.append_transfer(sender_sk=owner_sk, receiver_pk=receiver_pk)
    token.transfer_chain[0].receiver_pk = "tampered"

    assert token.validate_chain(issuer_pk) is False
