"""Policy configuration and validation helpers."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable policy caps for the offline CBDC prototype."""

    MAX_TX_VALUE: int = 1_000
    MAX_TOKEN_HOPS: int = 10
    MAX_WALLET_BALANCE: int = 10_000
    TOKEN_EXPIRY_SECONDS: int = 24 * 60 * 60


def is_not_expired(created_at: datetime, expiry_seconds: int) -> bool:
    """Return True if token is still within expiry period."""
    age = (datetime.now(tz=timezone.utc) - created_at).total_seconds()
    return age <= expiry_seconds
