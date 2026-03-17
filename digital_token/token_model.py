"""Token model and transfer-chain validation for the DPC PoC."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import json

from crypto.signatures import verify_signature
from digital_token.transfer_chain import TransferRecord


@dataclass
class Token:
    """Bearer token with issuer signature and an auditable transfer chain."""

    token_id: str
    value: int
    issuer_pk: str
    owner_pk: str
    expiry: str
    issuer_signature: str
    transfer_chain: list[TransferRecord] = field(default_factory=list)
    _locked: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._locked = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False) and name in {"token_id", "value"}:
            current = getattr(self, name)
            if current != value:
                raise AttributeError(f"{name} is immutable")
        super().__setattr__(name, value)

    # Backward-compatible aliases.
    @property
    def current_owner_pk(self) -> str:
        return self.owner_pk

    @current_owner_pk.setter
    def current_owner_pk(self, value: str) -> None:
        self.owner_pk = value

    @property
    def issuer_sig(self) -> str:
        return self.issuer_signature

    @issuer_sig.setter
    def issuer_sig(self, value: str) -> None:
        self.issuer_signature = value

    def issuance_dict(self) -> OrderedDict[str, object]:
        """Return deterministic issuance payload fields."""
        return OrderedDict(
            [
                ("token_id", self.token_id),
                ("value", self.value),
                ("issuer_pk", self.issuer_pk),
                ("owner_pk", self.owner_pk),
                ("expiry", self.expiry),
            ]
        )

    def issuance_payload(self) -> bytes:
        """Serialize issuance payload with deterministic JSON field ordering."""
        return json.dumps(self.issuance_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")

    def append_transfer(self, sender_sk: str, receiver_pk: str) -> TransferRecord:
        """Append a transfer signed by owner and update owner through the transfer chain."""
        sender_pk = self.owner_pk
        transfer = TransferRecord.create(
            token_id=self.token_id,
            sender_sk=sender_sk,
            sender_pk=sender_pk,
            receiver_pk=receiver_pk,
        )
        self.transfer_chain.append(transfer)
        self.owner_pk = receiver_pk
        return transfer

    def to_ordered_dict(self) -> OrderedDict[str, object]:
        """Return deterministic token JSON-serializable representation."""
        return OrderedDict(
            [
                ("token_id", self.token_id),
                ("value", self.value),
                ("issuer_pk", self.issuer_pk),
                ("owner_pk", self.owner_pk),
                ("expiry", self.expiry),
                ("issuer_signature", self.issuer_signature),
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
        if not verify_signature(self.issuer_pk, self.issuance_payload(), self.issuer_signature):
            return False

        owner_pk = self.owner_pk if not self.transfer_chain else None
        if self.transfer_chain:
            owner_pk = self.transfer_chain[0].sender_pk
            for transfer in self.transfer_chain:
                if transfer.token_id != self.token_id:
                    return False
                if not transfer.verify():
                    return False
                if transfer.sender_pk != owner_pk:
                    return False
                owner_pk = transfer.receiver_pk
            if owner_pk != self.owner_pk:
                return False
        return True
