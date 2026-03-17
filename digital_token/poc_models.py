"""Domain models for offline CBDC tokens and transfers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import uuid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class Token:
    """Bearer token representation."""

    token_id: str
    value: int
    issuer_pk: str
    owner_pk: str
    nonce: int
    issuer_signature: str
    hop_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    origin_token_id: str | None = None

    @staticmethod
    def new_unsigned(value: int, issuer_pk: str, owner_pk: str, nonce: int = 0) -> "Token":
        tid = str(uuid.uuid4())
        return Token(
            token_id=tid,
            value=value,
            issuer_pk=issuer_pk,
            owner_pk=owner_pk,
            nonce=nonce,
            issuer_signature="",
            hop_count=0,
            origin_token_id=tid,
        )

    def signing_payload(self) -> bytes:
        """Payload used for issuer minting signature."""
        return _canonical_json(
            {
                "token_id": self.token_id,
                "value": self.value,
                "issuer_pk": self.issuer_pk,
                "owner_pk": self.owner_pk,
                "nonce": self.nonce,
                "origin_token_id": self.origin_token_id,
            }
        )


@dataclass
class Transfer:
    """Token transfer event between wallets."""

    transfer_id: str
    token_id: str
    sender_pk: str
    receiver_pk: str
    nonce: int
    prev_transfer_id: str | None
    signature: str
    timestamp: datetime

    @staticmethod
    def unsigned(
        token_id: str,
        sender_pk: str,
        receiver_pk: str,
        nonce: int,
        prev_transfer_id: str | None,
    ) -> "Transfer":
        return Transfer(
            transfer_id=str(uuid.uuid4()),
            token_id=token_id,
            sender_pk=sender_pk,
            receiver_pk=receiver_pk,
            nonce=nonce,
            prev_transfer_id=prev_transfer_id,
            signature="",
            timestamp=datetime.now(tz=timezone.utc),
        )

    def signing_payload(self) -> bytes:
        """Payload used for sender signature."""
        return _canonical_json(
            {
                "transfer_id": self.transfer_id,
                "token_id": self.token_id,
                "sender_pk": self.sender_pk,
                "receiver_pk": self.receiver_pk,
                "nonce": self.nonce,
                "prev_transfer_id": self.prev_transfer_id,
                "timestamp": self.timestamp.isoformat(),
            }
        )


@dataclass
class PaymentBundle:
    """Collection of transfers exchanged atomically in offline mode."""

    bundle_id: str
    transfers: list[Transfer]
    tokens: dict[str, Token]

    @staticmethod
    def create(transfers: list[Transfer], tokens: dict[str, Token]) -> "PaymentBundle":
        return PaymentBundle(bundle_id=str(uuid.uuid4()), transfers=transfers, tokens=tokens)
