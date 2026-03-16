from dpc.issuer.mint import Issuer
from dpc.issuer.reconciliation import ReconciliationService
from dpc.token.token_model import Token
from dpc.token.transfer_chain import append_transfer
from dpc.wallet.wallet import Wallet

def test_double_spend_detection() -> None:
    issuer = Issuer()
    reconciler = ReconciliationService()
    a = Wallet("A")
    token = issuer.mint_token(a.public_key_hex, 1)

    ok, _ = reconciler.reconcile(token)
    assert ok

    ok_again, message = reconciler.reconcile(token)
    assert not ok_again
    assert message == "double-spend detected"

def test_rejects_fabricated_token_without_valid_issuer_signature() -> None:
    reconciler = ReconciliationService()
    forged = Token(
        token_id="forged",
        value=999,
        issuer_pk="00" * 32,
        owner_pk="11" * 32,
        expiry="2099-01-01T00:00:00+00:00",
        policy={"transferable": True},
        issuer_signature="deadbeef",
    )

    ok, message = reconciler.reconcile(forged)
    assert not ok
    assert message == "invalid issuer signature"

def test_reconcile_transferred_token_keeps_original_issuer_payload() -> None:
    issuer = Issuer()
    reconciler = ReconciliationService()
    a = Wallet("A")
    b = Wallet("B")
    token = issuer.mint_token(a.public_key_hex, 5)

    append_transfer(token, a.private_key, b.public_key_hex)

    ok, message = reconciler.reconcile(token)
    assert ok
    assert message == "ok"
