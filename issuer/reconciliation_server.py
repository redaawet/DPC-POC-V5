"""Settlement and reconciliation service when connectivity returns."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from copy import deepcopy
from typing import Callable

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


class RecoveryEngine:
    """Compute recoverable balance and re-issue funds after revocation wait window."""

    def __init__(self, server: "ReconciliationServer") -> None:
        self.server = server

    def revoke_wallet(self, public_key: str, *, at_time: datetime | None = None) -> None:
        self.server.revoked_wallets[public_key] = at_time or self.server.now_fn()

    def recovery_wait_elapsed(self, public_key: str, *, at_time: datetime | None = None) -> bool:
        revoked_at = self.server.revoked_wallets.get(public_key)
        if revoked_at is None:
            return False
        now = at_time or self.server.now_fn()
        wait_seconds = (now - revoked_at).total_seconds()
        return wait_seconds > self.server.policy.TOKEN_EXPIRY_SECONDS

    def reconstruct_safe_tokens(self, revoked_public_key: str) -> list[Token]:
        issued_for_wallet = [
            token
            for token in self.server.issuer.issued_tokens.values()
            if token.current_owner == revoked_public_key
        ]
        origin_ids_issued = {token.token_id for token in issued_for_wallet}

        externally_settled_origin_ids = {
            (token.origin_token_id or token.token_id)
            for transfer, token in self.server.accepted_transfers
            if (token.origin_token_id or token.token_id) in origin_ids_issued and transfer.receiver_pk != revoked_public_key
        }
        return [token for token in issued_for_wallet if token.token_id not in externally_settled_origin_ids]

    def reconstruct_safe_balance(self, revoked_public_key: str) -> int:
        return sum(token.value for token in self.reconstruct_safe_tokens(revoked_public_key))

    def reissue_recovered_balance(
        self,
        revoked_public_key: str,
        new_public_key: str,
        *,
        at_time: datetime | None = None,
    ) -> list[Token]:
        if not self.recovery_wait_elapsed(revoked_public_key, at_time=at_time):
            raise ValueError("RECOVERY_WAIT_NOT_ELAPSED")
        if (revoked_public_key, new_public_key) in self.server.recovery_reissued:
            return []

        safe_tokens = self.reconstruct_safe_tokens(revoked_public_key)
        reissued = [self.server.issuer.mint_token(owner_pk=new_public_key, value=token.value) for token in safe_tokens]
        self.server.recovery_reissued.add((revoked_public_key, new_public_key))
        return reissued


class ReconciliationServer:
    """Validates bundles, detects double spends, and keeps settlement ledger."""

    def __init__(
        self,
        issuer: Issuer,
        policy: PolicyConfig | None = None,
        *,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.issuer = issuer
        self.policy = policy or PolicyConfig()
        self.now_fn = now_fn or (lambda: datetime.now(tz=timezone.utc))
        self.ledger: dict[str, SettlementRecord] = {}
        self.accepted_chains: dict[str, tuple[str | None, str | None, int]] = {}
        self.transfer_hashes: dict[str, str] = {}
        self.accepted_transfers: list[tuple[Transfer, Token]] = []
        self.revoked_wallets: dict[str, datetime] = {}
        self.recovery_reissued: set[tuple[str, str]] = set()
        self.recovery_engine = RecoveryEngine(self)

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
            elif transfer.nonce > self.policy.MAX_HOPS:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "MAX_HOPS_EXCEEDED")
            elif transfer.parent_transfer_id != token.last_transfer_id:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BROKEN_PARENT_LINK")
            elif transfer.parent_transfer_hash != expected_prev_hash:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BROKEN_PARENT_HASH_LINK")
            elif transfer.prev_transfer_hash != expected_prev_hash:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "BROKEN_HASH_LINK")
            elif token.token_id in self.accepted_chains and self.accepted_chains[token.token_id] != chain_key:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "DOUBLE_SPEND", "CONFLICTING_CHAIN")
            elif token.token_id in self.ledger:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "DOUBLE_SPEND", "TOKEN_ALREADY_SETTLED")
            elif (int(self.now_fn().timestamp()) - token.issue_timestamp) > self.policy.TOKEN_EXPIRY_SECONDS:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "POLICY_VIOLATION", "TOKEN_EXPIRED")
            else:
                rec = SettlementRecord(token.token_id, transfer.transfer_id, "ACCEPTED", "OK")
                self.ledger[token.token_id] = rec
                self.accepted_chains[token.token_id] = chain_key
                self.transfer_hashes[transfer.transfer_id] = transfer.payload_hash()
                self.accepted_transfers.append((deepcopy(transfer), deepcopy(token)))

            results.append(rec)
        return results

    def revoke_wallet(self, public_key: str) -> None:
        """Revoke a lost/stolen wallet identity."""
        self.recovery_engine.revoke_wallet(public_key)

    def _recovery_wait_elapsed(self, public_key: str, *, at_time: datetime | None = None) -> bool:
        return self.recovery_engine.recovery_wait_elapsed(public_key, at_time=at_time)

    def reconstruct_safe_balance(self, revoked_public_key: str) -> int:
        """Compute safe recoverable balance for revoked wallet after settlement window."""
        return self.recovery_engine.reconstruct_safe_balance(revoked_public_key)

    def reissue_recovered_balance(
        self,
        revoked_public_key: str,
        new_public_key: str,
        *,
        at_time: datetime | None = None,
    ) -> list[Token]:
        """Mint replacement tokens after waiting window passes."""
        return self.recovery_engine.reissue_recovered_balance(
            revoked_public_key,
            new_public_key,
            at_time=at_time,
        )
