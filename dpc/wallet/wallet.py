from dpc.crypto.keys import generate_keypair, public_key_bytes
from dpc.token.transfer_chain import append_transfer
from dpc.token.token_model import Token
from dpc.wallet.ledger import Ledger


class Wallet:
    def __init__(self, name: str) -> None:
        self.name = name
        self.private_key, self.public_key = generate_keypair()
        self.public_key_hex = public_key_bytes(self.public_key)
        self.ledger = Ledger()

    def receive(self, token: Token) -> None:
        if token.owner_pk != self.public_key_hex:
            raise ValueError("token owner does not match wallet")
        self.ledger.add(token)

    def send(self, token_id: str, receiver: "Wallet") -> Token:
        token = self.ledger.pop(token_id)
        append_transfer(token, self.private_key, receiver.public_key_hex)
        receiver.receive(token)
        return token
