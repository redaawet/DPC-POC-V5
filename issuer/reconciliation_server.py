"""Settlement and reconciliation service when connectivity returns."""
from __future__ import annotations

from dataclasses import dataclass

from crypto.crypto_utils import verify
from issuer.issuer import Issuer
from digital_token.poc_models import PaymentBundle, Token, Transfer


@dataclass
class SettlementRecord:
    token_id: str
    transfer_id: str
    status: str
    reason: str


class ReconciliationServer:
    """Validates bundles, detects double spends, and keeps settlement ledger."""

    def __init__(self, issuer: Issuer) -> None:
        self.issuer = issuer
        self.ledger: dict[str, SettlementRecord] = {}

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

            if not self._verify_transfer(transfer):
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "REJECTED", "BAD_TRANSFER_SIG")
            elif not self._verify_issuer_root(token):
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "REJECTED", "BAD_ISSUER_SIG")
            elif token.token_id in self.ledger:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "DOUBLE_SPEND", "TOKEN_ALREADY_SETTLED")
            else:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "ACCEPTED", "OK")
                self.ledger[token.token_id] = rec

            results.append(rec)
        return results
