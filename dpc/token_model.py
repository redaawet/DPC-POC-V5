"""Token, transfer-record, receipt, and chain validation models."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from constants import GENESIS_HASH, JSON_SEPARATORS, MAX_OFFLINE_HOPS, NONCE_BYTES, TOKEN_TTL_SECONDS
from crypto_utils import ed25519_sign, ed25519_verify
from exceptions import ChainIntegrityError, HopLimitExceededError, SignatureVerificationError, TokenExpiredError


@dataclass
class Token:
    """Issuer-signed DPC bearer token.

    Parameters: token id, issuer public key, amount, issue/expiry times, and issuer signature.
    Returns: a serializable token object.
    Raises: TokenExpiredError from expiry checks.
    """

    token_id: str
    issuer_pubkey_hex: str
    amount_subunits: int
    issued_at: int
    ttl_expiry: int
    issuer_signature: str

    def is_expired(self, reference_time: int | None = None) -> bool:
        """Check whether this token is expired.

        Parameters: optional reference_time Unix timestamp.
        Returns: True when reference_time is after ttl_expiry, else False.
        Raises: TokenExpiredError when local time precedes issuer-signed issued_at.
        """
        now = reference_time if reference_time is not None else int(time.time())
        if now < self.issued_at:
            raise TokenExpiredError(
                f"Clock rollback detected: local time {now} precedes issuer-signed issuance timestamp {self.issued_at}. Transfer refused."
            )
        return now > self.ttl_expiry

    def genesis_payload_bytes(self) -> bytes:
        """Return canonical issuer-signed token bytes.

        Parameters: none.
        Returns: deterministic JSON bytes for token genesis fields.
        Raises: TypeError if fields are not JSON serializable.
        """
        payload = {
            "token_id": self.token_id,
            "issuer_pubkey_hex": self.issuer_pubkey_hex,
            "amount_subunits": self.amount_subunits,
            "issued_at": self.issued_at,
            "ttl_expiry": self.ttl_expiry,
        }
        # sort_keys=True gives byte-for-byte stable data before signature verification.
        return json.dumps(payload, sort_keys=True, separators=JSON_SEPARATORS).encode("utf-8")

    def verify_issuer_signature(self) -> None:
        """Verify the issuer signature over token genesis fields.

        Parameters: none.
        Returns: None on success.
        Raises: SignatureVerificationError when the issuer signature fails.
        """
        ed25519_verify(self.issuer_pubkey_hex, self.genesis_payload_bytes(), self.issuer_signature)

    def to_json(self) -> str:
        """Serialize this token as deterministic JSON.

        Parameters: none.
        Returns: JSON string sorted by key.
        Raises: TypeError if fields are not JSON serializable.
        """
        return json.dumps(asdict(self), sort_keys=True, separators=JSON_SEPARATORS)

    @classmethod
    def from_json(cls, s: str) -> "Token":
        """Deserialize a token from JSON.

        Parameters: s is the token JSON string.
        Returns: Token instance.
        Raises: json.JSONDecodeError or TypeError for invalid payloads.
        """
        return cls(**json.loads(s))

    @classmethod
    def mint_unsigned(cls, issuer_pubkey_hex: str, amount_subunits: int) -> "Token":
        """Create an unsigned token shell for issuer signing.

        Parameters: issuer public key and amount in subunits.
        Returns: Token with empty issuer signature.
        Raises: no custom exceptions.
        """
        issued_at = int(time.time())
        return cls(secrets.token_hex(16), issuer_pubkey_hex, amount_subunits, issued_at, issued_at + TOKEN_TTL_SECONDS, "")


@dataclass
class TransferRecord:
    """One signed hop in a DPC token transfer chain.

    Parameters: token id, hop index, sender/receiver keys, amount, nonce, previous hash, chain hash, signature.
    Returns: a transfer record whose chain_hash is recomputed during initialization.
    Raises: ChainIntegrityError from validation methods.
    """

    token_id: str
    hop_index: int
    sender_pubkey_hex: str
    receiver_pubkey_hex: str
    amount_subunits: int
    nonce: str = field(default_factory=lambda: secrets.token_hex(NONCE_BYTES))
    prev_hash: str = GENESIS_HASH
    chain_hash: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        """Compute the SHA-256 hash link for this transfer record.

        Parameters: none.
        Returns: None.
        Raises: ValueError if prev_hash is not valid hexadecimal.
        """
        self.chain_hash = self.compute_chain_hash()

    def payload_bytes(self) -> bytes:
        """Return deterministic bytes for the signed transfer payload.

        Parameters: none.
        Returns: canonical JSON payload bytes.
        Raises: TypeError if fields are not JSON serializable.
        """
        payload_dict = {
            "token_id": self.token_id,
            "hop_index": self.hop_index,
            "sender_pubkey_hex": self.sender_pubkey_hex,
            "receiver_pubkey_hex": self.receiver_pubkey_hex,
            "amount_subunits": self.amount_subunits,
            "nonce": self.nonce,
        }
        # sort_keys=True prevents semantically identical transfer payloads from signing different byte streams.
        return json.dumps(payload_dict, sort_keys=True, separators=JSON_SEPARATORS).encode("utf-8")

    def compute_chain_hash(self) -> str:
        """Compute the hash-linked chain digest for this record.

        Parameters: none.
        Returns: SHA-256 hex digest of payload bytes and previous hash bytes.
        Raises: ValueError if prev_hash is not valid hexadecimal.
        """
        # SHA-256 hash-linking binds this hop to all prior history, making earlier tampering invalidate later records.
        return hashlib.sha256(self.payload_bytes() + bytes.fromhex(self.prev_hash)).hexdigest()

    def sign(self, private_key_bytes: bytes) -> None:
        """Sign this transfer's chain hash.

        Parameters: private_key_bytes is the sender raw Ed25519 private key.
        Returns: None.
        Raises: cryptography backend exceptions if signing fails.
        """
        self.signature = ed25519_sign(private_key_bytes, bytes.fromhex(self.chain_hash))

    def verify_signature(self) -> None:
        """Verify this transfer's hash and Ed25519 signature.

        Parameters: none.
        Returns: None when valid.
        Raises: ChainIntegrityError for hash mismatch; SignatureVerificationError for invalid signature.
        """
        if self.chain_hash != self.compute_chain_hash():
            raise ChainIntegrityError("Transfer chain_hash mismatch")
        ed25519_verify(self.sender_pubkey_hex, bytes.fromhex(self.chain_hash), self.signature)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this transfer record to a dictionary.

        Parameters: none.
        Returns: JSON-compatible dict.
        Raises: no custom exceptions.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TransferRecord":
        """Deserialize a transfer record from a dictionary.

        Parameters: d is a JSON-compatible dictionary.
        Returns: TransferRecord with stored signature preserved.
        Raises: TypeError for missing or invalid fields.
        """
        record = cls(
            token_id=d["token_id"],
            hop_index=d["hop_index"],
            sender_pubkey_hex=d["sender_pubkey_hex"],
            receiver_pubkey_hex=d["receiver_pubkey_hex"],
            amount_subunits=d["amount_subunits"],
            nonce=d["nonce"],
            prev_hash=d["prev_hash"],
        )
        record.chain_hash = d["chain_hash"]
        record.signature = d["signature"]
        return record


@dataclass
class Receipt:
    """Local proof that a wallet accepted a token.

    Parameters: token id, received timestamp, final hop, full chain, redemption state, and token.
    Returns: receipt suitable for UTR storage.
    Raises: no custom exceptions.
    """

    token_id: str
    received_at: int
    final_hop: TransferRecord
    full_chain: list[TransferRecord]
    is_redeemed: bool = False
    token: Token | None = None

    def to_json(self) -> str:
        """Serialize this receipt as deterministic JSON.

        Parameters: none.
        Returns: JSON string.
        Raises: TypeError if fields are not serializable.
        """
        payload = {
            "token_id": self.token_id,
            "received_at": self.received_at,
            "final_hop": self.final_hop.to_dict(),
            "full_chain": [record.to_dict() for record in self.full_chain],
            "is_redeemed": self.is_redeemed,
            "token": asdict(self.token) if self.token is not None else None,
        }
        return json.dumps(payload, sort_keys=True, separators=JSON_SEPARATORS)

    @classmethod
    def from_json(cls, s: str) -> "Receipt":
        """Deserialize a receipt from JSON.

        Parameters: s is the receipt JSON.
        Returns: Receipt instance.
        Raises: json.JSONDecodeError or TypeError for invalid payloads.
        """
        d = json.loads(s)
        token = Token(**d["token"]) if d.get("token") is not None else None
        chain = [TransferRecord.from_dict(item) for item in d["full_chain"]]
        return cls(d["token_id"], d["received_at"], TransferRecord.from_dict(d["final_hop"]), chain, d["is_redeemed"], token)

    def chain_depth(self) -> int:
        """Return the number of records in the full chain.

        Parameters: none.
        Returns: chain length.
        Raises: no custom exceptions.
        """
        return len(self.full_chain)


class TransferChain:
    """Helper for validating and extending transfer chains.

    Parameters: ordered transfer records.
    Returns: chain wrapper.
    Raises: ChainIntegrityError and policy exceptions during validation.
    """

    def __init__(self, records: list[TransferRecord]) -> None:
        """Create a transfer-chain wrapper.

        Parameters: records is an ordered transfer chain.
        Returns: None.
        Raises: no custom exceptions.
        """
        self.records = records

    def validate_integrity(self, token: Token) -> None:
        """Validate chain ordering, hash links, signatures, token id, amount, and hop count.

        Parameters: token is the bearer token whose chain is being checked.
        Returns: None when valid.
        Raises: ChainIntegrityError, HopLimitExceededError, SignatureVerificationError, TokenExpiredError.
        """
        token.verify_issuer_signature()
        if not self.records:
            raise ChainIntegrityError("Transfer chain is empty")
        if self.records[-1].hop_index > MAX_OFFLINE_HOPS:
            raise HopLimitExceededError("Offline hop limit exceeded")

        previous_hash = GENESIS_HASH
        previous_hop = -1
        for position, record in enumerate(self.records):
            if record.token_id != token.token_id:
                raise ChainIntegrityError("Transfer token_id does not match token")
            if record.amount_subunits != token.amount_subunits:
                raise ChainIntegrityError("Transfer amount does not match token amount")
            if record.prev_hash != previous_hash:
                raise ChainIntegrityError("Transfer prev_hash does not link to prior chain_hash")
            if position == 0 and record.hop_index != 0:
                raise ChainIntegrityError("Genesis transfer must have hop_index 0")
            if position > 0 and record.hop_index != previous_hop + 1 and record.hop_index != 1:
                raise ChainIntegrityError("Transfer hop_index sequence is invalid")
            record.verify_signature()
            previous_hash = record.chain_hash
            previous_hop = record.hop_index

    def tip(self) -> TransferRecord:
        """Return the final transfer record.

        Parameters: none.
        Returns: last TransferRecord.
        Raises: ChainIntegrityError if the chain is empty.
        """
        if not self.records:
            raise ChainIntegrityError("Transfer chain is empty")
        return self.records[-1]

    def append(self, record: TransferRecord) -> None:
        """Append a record after local link checks.

        Parameters: record is the next transfer record.
        Returns: None.
        Raises: ChainIntegrityError when hop or hash linkage is invalid.
        """
        expected_prev = self.tip().chain_hash if self.records else GENESIS_HASH
        if record.prev_hash != expected_prev:
            raise ChainIntegrityError("Appended transfer prev_hash is invalid")
        if self.records and record.hop_index != self.tip().hop_index + 1 and record.hop_index != 1:
            raise ChainIntegrityError("Appended transfer hop_index is invalid")
        self.records.append(record)
