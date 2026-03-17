"""Atomic session flow for cash-like token payments."""

from __future__ import annotations

from copy import deepcopy
import json

from token.token_model import Token
from wallet.wallet import Wallet


class PaymentSession:
    """Coordinates sender payment and receiver-provided change with rollback."""

    def __init__(self, sender_wallet: Wallet, receiver_wallet: Wallet, price: int) -> None:
        self.sender_wallet = sender_wallet
        self.receiver_wallet = receiver_wallet
        self.price = price

    def execute(self) -> tuple[list[str], list[str]]:
        """Execute payment session atomically.

        Steps:
        1) price negotiation (already encoded as ``price``)
        2) sender sends tokens
        3) receiver computes and sends change tokens
        4) both wallets confirm via successful receive
        5) commit; rollback if any step fails
        """
        sender_utr = deepcopy(self.sender_wallet.utr)
        sender_str = deepcopy(self.sender_wallet.str)
        receiver_utr = deepcopy(self.receiver_wallet.utr)
        receiver_str = deepcopy(self.receiver_wallet.str)

        try:
            payment_payloads = self.sender_wallet.initiate_payment(self.price, self.receiver_wallet.owner_pk)
            for payload in payment_payloads:
                if not self.receiver_wallet.receive_token(payload):
                    raise ValueError("receiver rejected payment token")

            inbound_tokens = [_token_from_json(payload) for payload in payment_payloads]
            change_tokens = self.receiver_wallet.process_payment(tokens=inbound_tokens, price=self.price)
            change_payloads = self.receiver_wallet.send_tokens(self.sender_wallet.owner_pk, change_tokens)

            for payload in change_payloads:
                if not self.sender_wallet.receive_token(payload):
                    raise ValueError("sender rejected change token")

            return payment_payloads, change_payloads
        except Exception:
            self.sender_wallet.utr = sender_utr
            self.sender_wallet.str = sender_str
            self.receiver_wallet.utr = receiver_utr
            self.receiver_wallet.str = receiver_str
            raise


def _token_from_json(payload: str) -> Token:
    data = json.loads(payload)
    return Token(
        token_id=data["token_id"],
        value=data["value"],
        issuer_pk=data["issuer_pk"],
        owner_pk=data["owner_pk"],
        expiry=data["expiry"],
        issuer_signature=data["issuer_signature"],
        transfer_chain=[],
    )
