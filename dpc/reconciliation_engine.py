"""Issuer ledger and reconciliation engine for the DPC PoC."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from constants import GENESIS_HASH, JSON_SEPARATORS, MAX_SINGLE_TX_SUBUNITS, NONCE_BYTES, TOKEN_TTL_SECONDS
from crypto_utils import DPCKeyPair
from exceptions import FirstClaimConflictError, ReconciliationError, TransactionValueCapError, WalletStateError
from token_model import Token, TransferChain, TransferRecord


class IssuerLedger:
    """Central issuer simulator with first-valid-claim reconciliation.

    Parameters: none.
    Returns: ledger tracking minted, settled, pending, and blacklisted keys.
    Raises: no custom exceptions at construction.
    """

    def __init__(self) -> None:
        """Create an empty issuer ledger.

        Parameters: none.
        Returns: None.
        Raises: no custom exceptions.
        """
        self._minted: dict[str, dict[str, Any]] = {}
        self._settled: dict[str, dict[str, Any]] = {}
        self._blacklist: set[str] = set()
        self._pending: dict[str, list[dict[str, Any]]] = {}

    def mint_token(self, issuer_keypair: DPCKeyPair, receiver_pubkey_hex: str, amount_subunits: int) -> tuple[Token, list[TransferRecord]]:
        """Mint a new issuer-signed token and genesis transfer.

        Parameters: issuer keypair, receiver public key, and amount in subunits.
        Returns: Token and one-record genesis chain.
        Raises: TransactionValueCapError for non-positive or over-cap values.
        """
        if amount_subunits <= 0 or amount_subunits > MAX_SINGLE_TX_SUBUNITS:
            raise TransactionValueCapError("Mint amount exceeds transaction value cap")
        token = Token.mint_unsigned(issuer_keypair.public_key_hex(), amount_subunits)
        token.issuer_signature = issuer_keypair.sign(token.genesis_payload_bytes()).hex()
        genesis = TransferRecord(
            token_id=token.token_id,
            hop_index=0,
            sender_pubkey_hex=issuer_keypair.public_key_hex(),
            receiver_pubkey_hex=receiver_pubkey_hex,
            amount_subunits=amount_subunits,
            nonce=secrets.token_hex(NONCE_BYTES),
            prev_hash=GENESIS_HASH,
        )
        genesis.sign(issuer_keypair.private_key_bytes())
        self._minted[token.token_id] = {
            "amount": amount_subunits,
            "issuer_sig": token.issuer_signature,
            "issued_at": token.issued_at,
            "ttl": token.ttl_expiry,
        }
        return token, [genesis]

    def settle_token(self, claimer_pubkey_hex: str, token: Token, chain: list[TransferRecord]) -> dict[str, Any]:
        """Settle a submitted token using first-valid-claim conflict handling.

        Parameters: claimer public key, token, and full transfer chain.
        Returns: settlement dictionary.
        Raises: ReconciliationError or FirstClaimConflictError when settlement fails.
        """
        if token.token_id not in self._minted:
            raise ReconciliationError("Token was not minted by this issuer")
        TransferChain(chain).validate_integrity(token)
        if chain[-1].receiver_pubkey_hex != claimer_pubkey_hex:
            raise WalletStateError("Settlement claimer is not final receiver")
        if token.token_id in self._settled:
            existing = self._settled[token.token_id]
            if existing["claimer_pubkey"] == claimer_pubkey_hex:
                return existing
            # First-valid-claim wins; later conflicting claimers are blacklisted because offline systems cannot prove who copied the token.
            self._blacklist.add(claimer_pubkey_hex)
            self._pending.setdefault(token.token_id, []).append({"claimer_pubkey": claimer_pubkey_hex, "chain_depth": len(chain), "submitted_at": int(time.time())})
            raise FirstClaimConflictError("First valid claim already settled this token")
        settlement = {
            "token_id": token.token_id,
            "claimer_pubkey": claimer_pubkey_hex,
            "chain_depth": len(chain),
            "settled_at": int(time.time()),
        }
        self._settled[token.token_id] = settlement
        return settlement

    def proxy_sync(self, proxy_pubkey_hex: str, submissions: list[tuple[str, Token, list[TransferRecord]]]) -> list[dict[str, Any]]:
        """Settle multiple wallet submissions through a connected proxy.

        Parameters: proxy public key and tuples of claimer key, token, and chain.
        Returns: list of settlement dictionaries annotated with proxy key.
        Raises: ReconciliationError subclasses from individual settlement failures.
        """
        results: list[dict[str, Any]] = []
        for claimer_pubkey_hex, token, chain in submissions:
            result = dict(self.settle_token(claimer_pubkey_hex, token, chain))
            result["proxy_pubkey"] = proxy_pubkey_hex
            results.append(result)
        return results

    def get_settled_count(self) -> int:
        """Return the number of settled token ids.

        Parameters: none.
        Returns: integer count.
        Raises: no custom exceptions.
        """
        return len(self._settled)

    def is_blacklisted(self, pubkey_hex: str) -> bool:
        """Check if a public key has been blacklisted.

        Parameters: public key hex.
        Returns: True when blacklisted.
        Raises: no custom exceptions.
        """
        return pubkey_hex in self._blacklist

    def save(self, path: Path) -> None:
        """Persist issuer ledger state to JSON.

        Parameters: output path.
        Returns: None.
        Raises: OSError if writing fails.
        """
        payload = {
            "dpc_version": "1.0",
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": {
                "minted": self._minted,
                "settled": self._settled,
                "blacklist": sorted(self._blacklist),
                "pending": self._pending,
            },
        }
        path.write_text(json.dumps(payload, sort_keys=True, separators=JSON_SEPARATORS), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "IssuerLedger":
        """Load issuer ledger state from JSON.

        Parameters: input path.
        Returns: IssuerLedger instance.
        Raises: ReconciliationError for unsupported version; OSError/json errors for invalid files.
        """
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("dpc_version") != "1.0":
            raise ReconciliationError("Unsupported issuer ledger version")
        ledger = cls()
        data = payload["data"]
        ledger._minted = data["minted"]
        ledger._settled = data["settled"]
        ledger._blacklist = set(data["blacklist"])
        ledger._pending = data["pending"]
        return ledger
