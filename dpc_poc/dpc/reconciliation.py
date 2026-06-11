"""Issuer reconciliation engine implementing first-valid-claim double-spend prevention."""
from __future__ import annotations

from .crypto import ed25519_verify, hex_to_pubkey_bytes
from .models import Token
from .wallet import token_signature_message


class IssuerLedger:
    """
    Issuer's central ledger for CBDC reconciliation.
    Implements first-valid-claim: first legitimate owner wins, subsequent claims flagged as double-spend.
    """

    def __init__(self):
        """Initialize empty ledger, suspicious key registry, and audit log."""
        self.registry: dict[str, str] = {}         # token_id -> current_owner_pubkey
        self.token_values: dict[str, float] = {}   # token_id -> denomination
        self.accepted_tokens: dict[str, Token] = {}  # token_id -> token
        self.suspicious_keys: set[str] = set()     # flagged for double-spend attempts
        self.submission_log: list[dict] = []        # full audit trail

    def _valid_issuer_signature(self, token: Token) -> bool:
        """Verify issuer's Ed25519 signature for token authenticity."""
        return ed25519_verify(
            hex_to_pubkey_bytes(token.issuer_pubkey_hex),
            token_signature_message(
                token.token_id,
                token.issuer_pubkey_hex,
                token.issued_at,
                token.denomination,
            ),
            bytes.fromhex(token.issuer_signature_hex),
        )

    def submit_token(self, token: Token, submitter_pubkey_hex: str) -> dict:
        """
        Process a token submission for reconciliation.

        Returns result dict with accepted (bool), owner, and reason.
        Logic:
        1. Verify issuer signature (tamper detection)
        2. If new token: accept, register owner
        3. If re-submission by same owner: idempotent accept
        4. If different owner: CONFLICT - flag submitter and previous owner
        """
        if not self._valid_issuer_signature(token):
            result = {
                "token_id": token.token_id,
                "accepted": False,
                "owner": None,
                "reason": "invalid signature",
            }
            self.submission_log.append(result)
            return result

        if token.token_id not in self.registry:
            self.registry[token.token_id] = submitter_pubkey_hex
            self.token_values[token.token_id] = token.denomination
            self.accepted_tokens[token.token_id] = token
            result = {
                "token_id": token.token_id,
                "accepted": True,
                "owner": submitter_pubkey_hex,
                "reason": "accepted",
            }
        elif self.registry[token.token_id] == submitter_pubkey_hex:
            result = {
                "token_id": token.token_id,
                "accepted": True,
                "owner": submitter_pubkey_hex,
                "reason": "accepted",
            }
        else:
            # Double-spend conflict: flag the attacker and the previous owner
            if len(token.transfer_history) >= 2:
                self.suspicious_keys.add(token.transfer_history[-2])
            self.suspicious_keys.add(submitter_pubkey_hex)
            result = {
                "token_id": token.token_id,
                "accepted": False,
                "owner": self.registry[token.token_id],
                "reason": "Token already spent",
            }

        self.submission_log.append(result)
        return result

    def submit_batch(self, tokens: list[Token], submitter_pubkey_hex: str) -> list[dict]:
        """Submit multiple tokens at once."""
        return [self.submit_token(token, submitter_pubkey_hex) for token in tokens]

    def get_balance(self, owner_pubkey_hex: str) -> float:
        """Get total balance of tokens owned by a pubkey in the registry."""
        return sum(
            self.token_values[token_id]
            for token_id, owner in self.registry.items()
            if owner == owner_pubkey_hex
        )

    def is_flagged(self, pubkey_hex: str) -> bool:
        """Check if a pubkey is flagged for suspicious activity."""
        return pubkey_hex in self.suspicious_keys

    def print_report(self) -> None:
        """Print formatted audit report of all submissions."""
        print("[Ledger] Submission Report")
        print("[Ledger] token_id                         accepted owner    reason")
        for entry in self.submission_log:
            owner = (entry["owner"] or "")[:8]
            print(
                f"[Ledger] {entry['token_id'][:32]} {str(entry['accepted']):8} "
                f"{owner:8} {entry['reason']}"
            )
