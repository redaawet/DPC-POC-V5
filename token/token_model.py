"""Token model and transfer-chain validation for the DPC PoC."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import json

from crypto.signatures import verify_signature
from token.transfer_chain import TransferRecord


@dataclass
class Token:
    """Bearer token with issuer signature and an auditable transfer chain."""

    token_id: str
    value: int
    issuer_pk: str
    current_owner_pk: str
    expiry: str
    policy: dict
    issuer_sig: str
    transfer_chain: list[TransferRecord] = field(default_factory=list)

    def issuance_dict(self, original_owner_pk: str | None = None) -> OrderedDict[str, object]:
        """Return deterministic issuance payload fields."""
        owner_pk = self.current_owner_pk if original_owner_pk is None else original_owner_pk
        return OrderedDict(
            [
                ("token_id", self.token_id),
                ("value", self.value),
                ("issuer_pk", self.issuer_pk),
                ("current_owner_pk", owner_pk),
                ("expiry", self.expiry),
                ("policy", self.policy),
            ]
        )

    def issuance_payload(self, original_owner_pk: str | None = None) -> bytes:
        """Serialize issuance payload with deterministic JSON field ordering."""
        return json.dumps(
            self.issuance_dict(original_owner_pk=original_owner_pk),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def append_transfer(self, sender_sk: str, receiver_pk: str) -> TransferRecord:
        """Append a transfer signed by current owner and update current owner."""
        sender_pk = self.current_owner_pk
        transfer = TransferRecord.create(
            token_id=self.token_id,
            sender_sk=sender_sk,
            sender_pk=sender_pk,
            receiver_pk=receiver_pk,
        )
        self.transfer_chain.append(transfer)
        self.current_owner_pk = receiver_pk
        return transfer

    def to_ordered_dict(self) -> OrderedDict[str, object]:
        """Return deterministic token JSON-serializable representation."""
        return OrderedDict(
            [
                ("token_id", self.token_id),
                ("value", self.value),
                ("issuer_pk", self.issuer_pk),
                ("current_owner_pk", self.current_owner_pk),
                ("expiry", self.expiry),
                ("policy", self.policy),
                ("issuer_sig", self.issuer_sig),
                ("transfer_chain", [transfer.to_dict() for transfer in self.transfer_chain]),
            ]
        )

    def to_json(self) -> str:
        """Serialize token to deterministic JSON with stable key ordering."""
        return json.dumps(self.to_ordered_dict(), separators=(",", ":"), sort_keys=False)

    def validate_chain(self, issuer_pk: str) -> bool:
        """Validate issuer signature and each transfer continuity/signature."""
        if issuer_pk != self.issuer_pk:
            return False
        original_owner_pk = self.current_owner_pk
        if self.transfer_chain:
            original_owner_pk = self.transfer_chain[0].sender_pk

        if not verify_signature(
            self.issuer_pk,
            self.issuance_payload(original_owner_pk=original_owner_pk),
            self.issuer_sig,
        ):
            return False

        owner_pk = self.current_owner_pk if not self.transfer_chain else None
        if self.transfer_chain:
            owner_pk = self.transfer_chain[0].sender_pk
            for idx, transfer in enumerate(self.transfer_chain):
                if transfer.token_id != self.token_id:
                    return False
                if not transfer.verify():
                    return False
                if transfer.sender_pk != owner_pk:
                    return False
                owner_pk = transfer.receiver_pk
            if owner_pk != self.current_owner_pk:
                return False
        return True
