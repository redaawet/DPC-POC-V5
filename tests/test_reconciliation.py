from dpc.issuer.mint import Issuer
from dpc.issuer.reconciliation import ReconciliationService
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
