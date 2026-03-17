import pytest

pytest.importorskip("cryptography")

from crypto.signatures import generate_keypair, sign_message
from protocol.cash_payment import execute_cash_payment
from token.token_model import Token
from wallet.wallet import DictKeyStore, Wallet


def _mint_token(issuer_sk: str, issuer_pk: str, owner_pk: str, token_id: str, value: int) -> Token:
    token = Token(
        token_id=token_id,
        value=value,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())
    return token


def test_cash_like_change_handling() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    sender_sk, sender_pk = generate_keypair()
    receiver_sk, receiver_pk = generate_keypair()

    keystore = DictKeyStore()
    keystore.add_keypair(sender_sk, sender_pk)
    keystore.add_keypair(receiver_sk, receiver_pk)

    sender = Wallet(owner_pk=sender_pk, keystore=keystore)
    receiver = Wallet(owner_pk=receiver_pk, keystore=keystore)

    sender.add_token(_mint_token(issuer_sk, issuer_pk, sender_pk, token_id="s-10", value=10))
    receiver.add_token(_mint_token(issuer_sk, issuer_pk, receiver_pk, token_id="r-2a", value=2))
    receiver.add_token(_mint_token(issuer_sk, issuer_pk, receiver_pk, token_id="r-2b", value=2))
    receiver.add_token(_mint_token(issuer_sk, issuer_pk, receiver_pk, token_id="r-1", value=1))

    execute_cash_payment(sender_wallet=sender, receiver_wallet=receiver, price=6)

    assert sorted(token.value for token in sender.utr.values()) == [2, 2]
    assert sorted(token.value for token in receiver.utr.values()) == [1, 10]
