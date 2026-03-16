"""Reconciliation engine for submitted token settlement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from token.token_model import Token


@dataclass(frozen=True)
class Submission:
    """Submitted token plus optional submission timestamp."""

    source: str
    token: Token
    submitted_at: datetime


@dataclass(frozen=True)
class ReconciliationResult:
    """Settlement outcome for a submitted token."""

    source: str
    token_id: str
    status: str
    reason: str


class ReconciliationEngine:
    """Validates submitted tokens and rejects double-spends by token id."""

    def __init__(self, now_fn: Callable[[], datetime] | None = None) -> None:
        self._accepted_by_token_id: dict[str, datetime] = {}
        self._now_fn = now_fn or (lambda: datetime.now(tz=timezone.utc))

    def submit(self, source: str, token: Token, submitted_at: datetime | None = None) -> ReconciliationResult:
        """Validate a single token submission and return settlement result."""
        at = submitted_at or self._now_fn()

        if not token.validate_chain(token.issuer_pk):
            return ReconciliationResult(source=source, token_id=token.token_id, status="REJECTED", reason="INVALID_CHAIN")

        if not _is_not_expired(token.expiry, at):
            return ReconciliationResult(source=source, token_id=token.token_id, status="REJECTED", reason="EXPIRED")

        max_hops = int(token.policy.get("max_hops", 0))
        hop_count = len(token.transfer_chain)
        if hop_count > max_hops:
            return ReconciliationResult(source=source, token_id=token.token_id, status="REJECTED", reason="MAX_HOPS_EXCEEDED")

        first_valid_at = self._accepted_by_token_id.get(token.token_id)
        if first_valid_at is not None:
            return ReconciliationResult(source=source, token_id=token.token_id, status="REJECTED", reason="DUPLICATE_TOKEN_ID")

        self._accepted_by_token_id[token.token_id] = at
        return ReconciliationResult(source=source, token_id=token.token_id, status="ACCEPTED", reason="OK")


def _is_not_expired(expiry: str, at: datetime) -> bool:
    """Return True when token expiry is at or after settlement time."""
    expiry_dt = datetime.fromisoformat(expiry)
    if expiry_dt.tzinfo is None:
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
    return expiry_dt >= at
