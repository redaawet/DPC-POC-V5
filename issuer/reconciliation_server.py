"""Settlement and reconciliation service when connectivity returns."""
from __future__ import annotations

from dataclasses import dataclass

from crypto.crypto_utils import verify
from issuer.issuer import Issuer
from protocol.policy import PolicyConfig
from digital_token.poc_models import PaymentBundle, Token, Transfer


@dataclass
class SettlementRecord:
    token_id: str
    transfer_id: str
    status: str
    reason: str


class ReconciliationServer:
    """Validates bundles, detects double spends, and keeps settlement ledger."""

    def __init__(self, issuer: Issuer, policy: PolicyConfig | None = None) -> None:
        self.issuer = issuer
        self.policy = policy or PolicyConfig()
        self.ledger: dict[str, SettlementRecord] = {}
        self.accepted_chains: dict[str, tuple[str | None, str | None, int]] = {}
        self.transfer_hashes: dict[str, str] = {}

    def _verify_issuer_root(self, token: Token) -> bool:
        origin = token.origin_token_id or token.token_id
        root = self.issuer.issued_tokens.get(origin)
        if root is None:
            return False
        return verify(root.signing_payload(), root.issuer_signature, self.issuer.public_key_hex)

    def _verify_transfer(self, transfer: Transfer) -> bool:
        return verify(transfer.signing_payload(), transfer.signature, transfer.sender_pk)

    def process_bundle(self, bundle: PaymentBundle) -> list[SettlementRecord]:
        """Process a payment bundle and return settlement records."""
        results: list[SettlementRecord] = []
        for transfer in bundle.transfers:
            token = bundle.tokens[transfer.token_id]
            expected_prev_hash = token.last_transfer_hash
            chain_key = (transfer.parent_transfer_id, transfer.prev_transfer_hash, transfer.hop_count)

            if not self._verify_transfer(transfer):
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BAD_TRANSFER_SIG")
            elif not self._verify_issuer_root(token):
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BAD_ISSUER_SIG")
            elif transfer.hop_count > self.policy.MAX_HOPS:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "MAX_HOPS_EXCEEDED")
            elif transfer.parent_transfer_id != token.last_transfer_id:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BROKEN_PARENT_LINK")
            elif transfer.prev_transfer_hash != expected_prev_hash:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BROKEN_HASH_LINK")
            elif token.token_id in self.accepted_chains and self.accepted_chains[token.token_id] != chain_key:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "DOUBLE_SPEND", "CONFLICTING_CHAIN")
            elif token.token_id in self.ledger:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "DOUBLE_SPEND", "TOKEN_ALREADY_SETTLED")
            else:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "ACCEPTED", "OK")
                self.ledger[token.token_id] = rec
                self.accepted_chains[token.token_id] = chain_key
                self.transfer_hashes[transfer.transfer_id] = transfer.payload_hash()

            results.append(rec)
        return results
