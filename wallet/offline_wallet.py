"""Wallet implementation with offline payment, policy checks, and replay protection."""
from __future__ import annotations

from copy import deepcopy
from typing import Iterable

from crypto.crypto_utils import sign, verify
from protocol.policy import PolicyConfig, is_not_expired
from digital_token.poc_models import PaymentBundle, Token, Transfer


class Wallet:
    """A mobile wallet maintaining unspent and spent token registers."""

    def __init__(self, owner_name: str, private_key_hex: str, public_key_hex: str, policy: PolicyConfig) -> None:
        self.owner_name = owner_name
        self.private_key_hex = private_key_hex
        self.public_key_hex = public_key_hex
        self.policy = policy

        self.utr: dict[str, Token] = {}
        self.str: dict[str, Token] = {}
        self.transfer_history: dict[str, str | None] = {}
        self.processed_transfer_ids: set[str] = set()

    def receive_token(self, token: Token) -> None:
        """Receive an unspent token into UTR with balance-cap policy enforcement."""
        if self.balance() + token.value > self.policy.MAX_WALLET_BALANCE:
            raise ValueError("MAX_WALLET_BALANCE exceeded")
        self.utr[token.token_id] = deepcopy(token)

    def balance(self) -> int:
        """Return available wallet balance from UTR."""
        return sum(token.value for token in self.utr.values())

    def select_tokens(self, amount: int) -> list[Token]:
        """Greedy token selection for a payment amount (no token splitting)."""
        selected: list[Token] = []
        total = 0
        for token in sorted(self.utr.values(), key=lambda t: t.value):
            selected.append(token)
            total += token.value
            if total >= amount:
                return selected
        raise ValueError("Insufficient funds")

    def create_payment(self, receiver_pk: str, amount: int) -> PaymentBundle:
        """Create a signed payment bundle for receiver using whole tokens only."""
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount > self.policy.MAX_TX_VALUE:
            raise ValueError("MAX_TX_VALUE exceeded")

        selected = self.select_tokens(amount)
        transfers: list[Transfer] = []
        outbound_tokens: dict[str, Token] = {}

        for token in selected:
            self.utr.pop(token.token_id)
            self.str[token.token_id] = token

            spend_token = deepcopy(token)
            spend_token.owner_pk = receiver_pk
            spend_token.hop_count += 1
            spend_token.nonce += 1

            transfer = Transfer.unsigned(
                token_id=spend_token.token_id,
                sender_pk=self.public_key_hex,
                receiver_pk=receiver_pk,
                nonce=spend_token.nonce,
                prev_transfer_id=self.transfer_history.get(token.token_id),
            )
            transfer.signature = sign(transfer.signing_payload(), self.private_key_hex)

            self.transfer_history[spend_token.token_id] = transfer.transfer_id
            transfers.append(transfer)
            outbound_tokens[spend_token.token_id] = spend_token

        return PaymentBundle.create(transfers=transfers, tokens=outbound_tokens)

    def verify_transfer(self, transfer: Transfer, token: Token) -> bool:
        """Verify transfer signature and policy constraints."""
        if transfer.transfer_id in self.processed_transfer_ids:
            return False
        if transfer.receiver_pk != self.public_key_hex:
            return False
        if token.hop_count > self.policy.MAX_TOKEN_HOPS:
            return False
        if not is_not_expired(token.created_at, self.policy.TOKEN_EXPIRY_SECONDS):
            return False
        if not verify(transfer.signing_payload(), transfer.signature, transfer.sender_pk):
            return False
        return True

    def apply_transfer(self, transfer: Transfer, token: Token) -> bool:
        """Apply verified transfer into wallet state."""
        if not self.verify_transfer(transfer, token):
            return False
        if self.balance() + token.value > self.policy.MAX_WALLET_BALANCE:
            return False
        self.utr[token.token_id] = deepcopy(token)
        self.transfer_history[token.token_id] = transfer.transfer_id
        self.processed_transfer_ids.add(transfer.transfer_id)
        return True

    def receive_bundle(self, bundle: PaymentBundle) -> list[tuple[str, bool]]:
        """Apply all transfers from a payment bundle."""
        results: list[tuple[str, bool]] = []
        for transfer in bundle.transfers:
            token = bundle.tokens[transfer.token_id]
            ok = self.apply_transfer(transfer, token)
            results.append((transfer.transfer_id, ok))
        return results

    def snapshot_tokens(self) -> Iterable[Token]:
        """Helper for demos and debug output."""
        return list(self.utr.values())
