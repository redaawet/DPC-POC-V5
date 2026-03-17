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


def test_token_is_transferable_across_multiple_offline_hops() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()
    carol_sk, carol_pk = generate_keypair()
    _dave_sk, dave_pk = generate_keypair()

    token = Token(
        token_id="tok-003",
        value=30,
        issuer_pk=issuer_pk,
        owner_pk=alice_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())

    token.append_transfer(sender_sk=alice_sk, receiver_pk=bob_pk)
    token.append_transfer(sender_sk=bob_sk, receiver_pk=carol_pk)
    token.append_transfer(sender_sk=carol_sk, receiver_pk=dave_pk)

    assert token.owner_pk == dave_pk
    assert token.validate_chain(issuer_pk) is True


def test_validate_chain_fails_when_parent_hash_link_is_tampered() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    owner_sk, owner_pk = generate_keypair()
    receiver_sk, receiver_pk = generate_keypair()
    _third_sk, third_pk = generate_keypair()

    token = Token(
        token_id="tok-004",
        value=15,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())

    token.append_transfer(sender_sk=owner_sk, receiver_pk=receiver_pk)
    token.append_transfer(sender_sk=receiver_sk, receiver_pk=third_pk)
    token.transfer_chain[1].prev_transfer_hash = "00" * 32

    assert token.validate_chain(issuer_pk) is False
