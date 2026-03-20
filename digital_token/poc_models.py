"""Domain models for offline CBDC tokens and transfers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
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
    current_owner: str
    nonce: int
    issuer_signature: str
    last_transfer_id: str | None = None
    last_transfer_hash: str | None = None
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
            current_owner=owner_pk,
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
                "owner_pk": self.current_owner,
                "nonce": self.nonce,
                "origin_token_id": self.origin_token_id,
            }
        )

    @property
    def owner_pk(self) -> str:
        """Backward-compatible alias for current owner public key."""
        return self.current_owner

    @owner_pk.setter
    def owner_pk(self, value: str) -> None:
        self.current_owner = value


@dataclass
class Transfer:
    """Token transfer event between wallets."""

    transfer_id: str
    token_id: str
    sender_pk: str
    receiver_pk: str
    nonce: int
    parent_transfer_id: str | None
    prev_transfer_hash: str | None
    hop_count: int
    signature: str
    timestamp: datetime

    @staticmethod
    def unsigned(
        token_id: str,
        sender_pk: str,
        receiver_pk: str,
        nonce: int,
        parent_transfer_id: str | None,
        prev_transfer_hash: str | None,
        hop_count: int,
    ) -> "Transfer":
        return Transfer(
            transfer_id=str(uuid.uuid4()),
            token_id=token_id,
            sender_pk=sender_pk,
            receiver_pk=receiver_pk,
            nonce=nonce,
            parent_transfer_id=parent_transfer_id,
            prev_transfer_hash=prev_transfer_hash,
            hop_count=hop_count,
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
                "parent_transfer_id": self.parent_transfer_id,
                "prev_transfer_hash": self.prev_transfer_hash,
                "hop_count": self.hop_count,
                "timestamp": self.timestamp.isoformat(),
            }
        )

    def payload_hash(self) -> str:
        """Compute deterministic hash of transfer payload including signature."""
        payload = _canonical_json(
            {
                "transfer_id": self.transfer_id,
                "token_id": self.token_id,
                "sender_pk": self.sender_pk,
                "receiver_pk": self.receiver_pk,
                "nonce": self.nonce,
                "parent_transfer_id": self.parent_transfer_id,
                "prev_transfer_hash": self.prev_transfer_hash,
                "hop_count": self.hop_count,
                "timestamp": self.timestamp.isoformat(),
                "signature": self.signature,
            }
        )
        return hashlib.sha256(payload).hexdigest()


@dataclass
class PaymentBundle:
    """Collection of transfers exchanged atomically in offline mode."""

    bundle_id: str
    transfers: list[Transfer]
    tokens: dict[str, Token]

    @staticmethod
    def create(transfers: list[Transfer], tokens: dict[str, Token]) -> "PaymentBundle":
        return PaymentBundle(bundle_id=str(uuid.uuid4()), transfers=transfers, tokens=tokens)
