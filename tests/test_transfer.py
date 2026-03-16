from dpc.issuer.mint import Issuer
from dpc.protocol.transfer_protocol import LocalChannel, transfer_over_channel
from dpc.token.transfer_chain import validate_transfer_chain
from dpc.wallet.wallet import Wallet


def test_end_to_end_transfer() -> None:
    issuer = Issuer()
    a, b, c = Wallet("A"), Wallet("B"), Wallet("C")
    token = issuer.mint_token(a.public_key_hex, 7)
    a.receive(token)

    channel = LocalChannel()
    transfer_over_channel(a, b, token.token_id, channel)
    transfer_over_channel(b, c, token.token_id, channel)

    final = c.ledger.get(token.token_id)
    assert final.owner_pk == c.public_key_hex
    assert validate_transfer_chain(final)
