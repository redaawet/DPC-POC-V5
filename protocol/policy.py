"""Policy configuration and validation helpers."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable policy caps for the offline CBDC prototype."""

    MAX_TX_VALUE: int = 1_000
    MAX_HOPS: int = 3
    MAX_BALANCE: int = 50
    MAX_TOKEN_HOPS: int | None = None
    MAX_WALLET_BALANCE: int | None = None
    TOKEN_EXPIRY_SECONDS: int = 24 * 60 * 60

    def __post_init__(self) -> None:
        if self.MAX_TOKEN_HOPS is not None:
            object.__setattr__(self, "MAX_HOPS", self.MAX_TOKEN_HOPS)
        if self.MAX_WALLET_BALANCE is not None:
            object.__setattr__(self, "MAX_BALANCE", self.MAX_WALLET_BALANCE)


def is_not_expired(created_at: datetime, expiry_seconds: int) -> bool:
    """Return True if token is still within expiry period."""
    age = (datetime.now(tz=timezone.utc) - created_at).total_seconds()
    return age <= expiry_seconds
