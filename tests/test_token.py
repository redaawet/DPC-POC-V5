from dpc.issuer.mint import Issuer
from dpc.token.transfer_chain import append_transfer, validate_transfer_chain
from dpc.wallet.wallet import Wallet


def test_token_issuance() -> None:
    issuer = Issuer()
    wallet = Wallet("A")
    token = issuer.mint_token(wallet.public_key_hex, 100)
    assert token.owner_pk == wallet.public_key_hex
    assert token.transfer_chain == []


def test_transfer_chain_validation() -> None:
    issuer = Issuer()
    a = Wallet("A")
    b = Wallet("B")
    token = issuer.mint_token(a.public_key_hex, 100)
    append_transfer(token, a.private_key, b.public_key_hex)
    assert validate_transfer_chain(token)
