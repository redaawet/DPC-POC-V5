import pytest

pytest.importorskip("cryptography")

from crypto.signatures import generate_keypair, sign_message
from protocol.transfer_protocol import Channel, transfer_over_channel
from digital_token.token_model import Token
from wallet.wallet import DictKeyStore, Wallet


def _issued_token(issuer_sk: str, issuer_pk: str, owner_pk: str, token_id: str = "tok-proto") -> Token:
    token = Token(
        token_id=token_id,
        value=75,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())
    return token


def test_channel_two_phase_transfer_wallet_a_to_b() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()

    keystore = DictKeyStore()
    keystore.add_keypair(alice_sk, alice_pk)
    keystore.add_keypair(bob_sk, bob_pk)

    wallet_a = Wallet(owner_pk=alice_pk, keystore=keystore)
    wallet_b = Wallet(owner_pk=bob_pk, keystore=keystore)

    token = _issued_token(issuer_sk, issuer_pk, alice_pk)
    wallet_a.add_token(token)

    channel = Channel()
    ok = transfer_over_channel(wallet_a, wallet_b, channel, nonce=11)

    assert ok is True
    assert token.token_id not in wallet_a.utr
    assert token.token_id in wallet_a.str
    assert token.token_id in wallet_b.utr
    assert wallet_b.utr[token.token_id].validate_chain(issuer_pk) is True
