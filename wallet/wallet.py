"""Wallet model with UTR/STR state and keystore-backed transfer signing."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import json
from typing import Protocol

from dpc_token.token_model import Token
from dpc_token.transfer_chain import TransferRecord


class KeyStore(Protocol):
    """Protocol for private-key lookup by owner public key."""

    def get_private_key(self, public_key: str) -> str:
        """Return base64 encoded private key for the provided public key."""


@dataclass
class DictKeyStore:
    """Simple in-memory key store used in tests and demos."""

    keys: dict[str, str] = field(default_factory=dict)

    def add_keypair(self, private_key: str, public_key: str) -> None:
        """Store a private/public key pair."""
        self.keys[public_key] = private_key

    def get_private_key(self, public_key: str) -> str:
        """Resolve private key for a public key or raise KeyError."""
        return self.keys[public_key]


class Wallet:
    """Wallet maintaining an unspent token register (UTR) and spent token register (STR)."""

    def __init__(self, owner_pk: str, keystore: KeyStore) -> None:
        self.owner_pk = owner_pk
        self.keystore = keystore
        self.utr: dict[str, Token] = {}
        self.str: dict[str, Token] = {}

    def add_token(self, token: Token) -> None:
        """Add a token to UTR after ownership and signature-chain validation."""
        if token.current_owner_pk != self.owner_pk:
            raise ValueError("token is not owned by this wallet")
        if not token.validate_chain(token.issuer_pk):
            raise ValueError("invalid token transfer chain")
        self.utr[token.token_id] = deepcopy(token)

    def send_token(self, receiver_pk: str) -> str:
        """Send one token by moving it UTR->STR and appending a signed transfer record."""
        if not self.utr:
            raise ValueError("no tokens available to send")

        token_id = sorted(self.utr.keys())[0]
        token = self.utr.pop(token_id)
        previous_owner = token.current_owner_pk

        try:
            sender_sk = self.keystore.get_private_key(self.owner_pk)
            token.append_transfer(sender_sk=sender_sk, receiver_pk=receiver_pk)
        except Exception:
            self.utr[token_id] = token
            token.current_owner_pk = previous_owner
            raise

        self.str[token_id] = deepcopy(token)
        return token.to_json()

    def receive_token(self, payload: str) -> bool:
        """Receive a token payload atomically.

        Any parse/validation failure restores prior wallet state and returns ``False``.
        """
        utr_before = deepcopy(self.utr)
        str_before = deepcopy(self.str)

        try:
            token = _token_from_payload(payload)
            if token.current_owner_pk != self.owner_pk:
                raise ValueError("token receiver does not match wallet owner")
            if not token.validate_chain(token.issuer_pk):
                raise ValueError("invalid token transfer chain")
            if token.token_id in self.str:
                raise ValueError("token already spent by this wallet")
            self.utr[token.token_id] = token
            return True
        except Exception:
            self.utr = utr_before
            self.str = str_before
            return False

    def sync(self, settled_token_ids: list[str]) -> None:
        """Sync local STR against settlement by removing settled token IDs."""
        for token_id in settled_token_ids:
            self.str.pop(token_id, None)


def _token_from_payload(payload: str) -> Token:
    """Deserialize a token payload JSON string into a ``Token`` instance."""
    data = json.loads(payload)
    transfer_chain = [TransferRecord(**record) for record in data.get("transfer_chain", [])]
    return Token(
        token_id=data["token_id"],
        value=data["value"],
        issuer_pk=data["issuer_pk"],
        initial_owner_pk=data.get("initial_owner_pk"),
        current_owner_pk=data["current_owner_pk"],
        expiry=data["expiry"],
        policy=data["policy"],
        issuer_sig=data["issuer_sig"],
        transfer_chain=transfer_chain,
    )
