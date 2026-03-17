import json

import pytest

pytest.importorskip("cryptography")

from crypto.signatures import generate_keypair, sign_message
from digital_token.token_model import Token
from wallet.wallet import DictKeyStore, Wallet


def _issued_token(issuer_sk: str, issuer_pk: str, owner_pk: str, token_id: str = "tok-w1") -> Token:
    token = Token(
        token_id=token_id,
        value=50,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())
    return token


def test_wallet_withdraw_send_receive_and_sync_flow() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()

    keystore = DictKeyStore()
    keystore.add_keypair(alice_sk, alice_pk)
    keystore.add_keypair(bob_sk, bob_pk)

    alice_wallet = Wallet(owner_pk=alice_pk, keystore=keystore)
    bob_wallet = Wallet(owner_pk=bob_pk, keystore=keystore)

    # withdraw/add token into sender wallet UTR
    token = _issued_token(issuer_sk, issuer_pk, alice_pk)
    alice_wallet.add_token(token)
    assert list(alice_wallet.utr) == [token.token_id]

    # send removes from UTR, appends transfer, and parks in STR
    payload = alice_wallet.send_token(receiver_pk=bob_pk)
    assert token.token_id not in alice_wallet.utr
    assert token.token_id in alice_wallet.str

    # receive validates chain and stores in receiver UTR
    received = bob_wallet.receive_token(payload)
    assert received is True
    assert token.token_id in bob_wallet.utr

    # sync clears sender STR after settlement acknowledgement
    alice_wallet.sync([token.token_id])
    assert token.token_id not in alice_wallet.str


def test_receive_is_atomic_and_rolls_back_on_failure() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()

    keystore = DictKeyStore()
    keystore.add_keypair(alice_sk, alice_pk)
    keystore.add_keypair(bob_sk, bob_pk)

    bob_wallet = Wallet(owner_pk=bob_pk, keystore=keystore)
    existing = _issued_token(issuer_sk, issuer_pk, bob_pk, token_id="tok-existing")
    bob_wallet.add_token(existing)

    sent_to_alice = _issued_token(issuer_sk, issuer_pk, alice_pk, token_id="tok-new")
    bad_payload = sent_to_alice.to_json()

    # Corrupt receiver without resigning so validation fails.
    mutated = json.loads(bad_payload)
    mutated["owner_pk"] = bob_pk
    bad_payload = json.dumps(mutated)

    before_keys = sorted(bob_wallet.utr.keys())
    received = bob_wallet.receive_token(bad_payload)

    assert received is False
    assert sorted(bob_wallet.utr.keys()) == before_keys
