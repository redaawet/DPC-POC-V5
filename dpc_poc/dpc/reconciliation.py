from __future__ import annotations

from .crypto import ed25519_verify, hex_to_pubkey_bytes
from .models import Token
from .wallet import token_signature_message


class IssuerLedger:
    def __init__(self):
        self.registry: dict[str, str] = {}
        self.token_values: dict[str, float] = {}
        self.accepted_tokens: dict[str, Token] = {}
        self.suspicious_keys: set[str] = set()
        self.submission_log: list[dict] = []

    def _valid_issuer_signature(self, token: Token) -> bool:
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
        return [self.submit_token(token, submitter_pubkey_hex) for token in tokens]

    def get_balance(self, owner_pubkey_hex: str) -> float:
        return sum(
            self.token_values[token_id]
            for token_id, owner in self.registry.items()
            if owner == owner_pubkey_hex
        )

    def is_flagged(self, pubkey_hex: str) -> bool:
        return pubkey_hex in self.suspicious_keys

    def print_report(self) -> None:
        print("[Ledger] Submission Report")
        print("[Ledger] token_id                         accepted owner    reason")
        for entry in self.submission_log:
            owner = (entry["owner"] or "")[:8]
            print(
                f"[Ledger] {entry['token_id'][:32]} {str(entry['accepted']):8} "
                f"{owner:8} {entry['reason']}"
            )
