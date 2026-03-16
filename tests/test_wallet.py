from dpc.issuer.mint import Issuer
from dpc.wallet.wallet import Wallet


def test_wallet_send_receive() -> None:
    issuer = Issuer()
    a = Wallet("A")
    b = Wallet("B")
    token = issuer.mint_token(a.public_key_hex, 42)
    a.receive(token)
    sent = a.send(token.token_id, b)
    assert b.ledger.has(sent.token_id)
    assert not a.ledger.has(sent.token_id)
