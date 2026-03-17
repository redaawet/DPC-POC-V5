from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from crypto.signatures import generate_keypair, sign_message
from issuer.reconciliation import ReconciliationEngine
from digital_token.token_model import Token


def _issued_token(issuer_sk: str, issuer_pk: str, owner_pk: str, *, token_id: str = "tok-recon") -> Token:
    token = Token(
        token_id=token_id,
        value=100,
        issuer_pk=issuer_pk,
        owner_pk=owner_pk,
        expiry="2030-01-01T00:00:00+00:00",
        issuer_signature="",
        transfer_chain=[],
    )
    token.issuer_signature = sign_message(issuer_sk, token.issuance_payload())
    return token


def test_reconciliation_accepts_first_valid_duplicate_and_rejects_second() -> None:
    issuer_sk, issuer_pk = generate_keypair()
    owner_sk, owner_pk = generate_keypair()
    _w1_sk, wallet1_pk = generate_keypair()
    _w2_sk, wallet2_pk = generate_keypair()

    root = _issued_token(issuer_sk, issuer_pk, owner_pk, token_id="double-spend-1")

    spend_to_w1 = deepcopy(root)
    spend_to_w1.append_transfer(sender_sk=owner_sk, receiver_pk=wallet1_pk)

    spend_to_w2 = deepcopy(root)
    spend_to_w2.append_transfer(sender_sk=owner_sk, receiver_pk=wallet2_pk)

    now = datetime(2029, 1, 1, tzinfo=timezone.utc)
    engine = ReconciliationEngine(now_fn=lambda: now)

    first = engine.submit(source="wallet-1", token=spend_to_w1, submitted_at=now)
    second = engine.submit(source="wallet-2", token=spend_to_w2, submitted_at=now + timedelta(seconds=10))

    assert first.status == "ACCEPTED"
    assert first.reason == "OK"

    assert second.status == "REJECTED"
    assert second.reason == "DUPLICATE_TOKEN_ID"
