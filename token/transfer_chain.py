"""Transfer-chain models and deterministic serialization helpers."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import uuid

from crypto.signatures import sign_message, verify_signature


@dataclass
class TransferRecord:
    """A single transfer event in a token's custody chain."""

    transfer_id: str
    token_id: str
    sender_pk: str
    receiver_pk: str
    timestamp: str
    signature: str

    @staticmethod
    def create(token_id: str, sender_sk: str, sender_pk: str, receiver_pk: str) -> "TransferRecord":
        """Create and sign a transfer record."""
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        transfer = TransferRecord(
            transfer_id=str(uuid.uuid4()),
            token_id=token_id,
            sender_pk=sender_pk,
            receiver_pk=receiver_pk,
            timestamp=timestamp,
            signature="",
        )
        transfer.signature = sign_message(sender_sk, transfer.signing_payload())
        return transfer

    def signing_dict(self) -> OrderedDict[str, str]:
        """Return deterministic transfer-signing payload as ordered fields."""
        return OrderedDict(
            [
                ("transfer_id", self.transfer_id),
                ("token_id", self.token_id),
                ("sender_pk", self.sender_pk),
                ("receiver_pk", self.receiver_pk),
                ("timestamp", self.timestamp),
            ]
        )

    def signing_payload(self) -> bytes:
        """Serialize transfer-signing payload to deterministic UTF-8 JSON bytes."""
        return json.dumps(self.signing_dict(), separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> OrderedDict[str, str]:
        """Return deterministic transfer record representation including signature."""
        payload = self.signing_dict()
        payload["signature"] = self.signature
        return payload

    def verify(self) -> bool:
        """Verify this transfer record's sender signature."""
        return verify_signature(self.sender_pk, self.signing_payload(), self.signature)
