"""Wallet and local unspent-token register for the DPC PoC."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from constants import GENESIS_HASH, JSON_SEPARATORS, MAX_OFFLINE_HOPS, MAX_SINGLE_TX_SUBUNITS, MAX_WALLET_BALANCE_SUBUNITS, NONCE_BYTES, SUBUNITS_PER_ETB
from crypto_utils import DPCKeyPair
from exceptions import DPCError, DoubleSpendError, HopLimitExceededError, InsufficientFundsError, TokenExpiredError, TransactionValueCapError, WalletBalanceCapError, WalletStateError
from token_model import Receipt, Token, TransferChain, TransferRecord


class UnspentTokenRegister:
    """Local Unspent Token Register for wallet-owned receipts.

    Parameters: wallet_id identifies the owning wallet.
    Returns: local register with receipt, spent-token, and nonce indexes.
    Raises: no custom exceptions at construction.
    """

    def __init__(self, wallet_id: str) -> None:
        """Create an empty UTR.

        Parameters: wallet_id is a local wallet label.
        Returns: None.
        Raises: no custom exceptions.
        """
        self.wallet_id = wallet_id
        self._entries: dict[str, Receipt] = {}
        self._spent_token_ids: set[str] = set()
        self._seen_nonces: set[str] = set()

    def add_receipt(self, receipt: Receipt) -> None:
        """Add a validated receipt to the UTR.

        Parameters: receipt contains the accepted token and transfer chain.
        Returns: None.
        Raises: DoubleSpendError for replay/spent tokens; WalletBalanceCapError for balance cap violations.
        """
        is_returning_token = receipt.token_id in self._spent_token_ids
        if receipt.token_id in self._entries:
            raise DoubleSpendError("Token is already unspent in this wallet")
        if receipt.token_id in self._spent_token_ids and receipt.full_chain[-1].nonce in self._seen_nonces:
            raise DoubleSpendError("Token was already spent by this wallet")
        incoming_nonces = {record.nonce for record in receipt.full_chain}
        # The seen-nonces check detects replayed transfer chains even when token ids are copied.
        if is_returning_token:
            nonce_conflicts = {receipt.full_chain[-1].nonce}.intersection(self._seen_nonces)
        else:
            nonce_conflicts = self._seen_nonces.intersection(incoming_nonces)
        if nonce_conflicts:
            raise DoubleSpendError("Replay attack: nonce already seen")
        token_amount = receipt.token.amount_subunits if receipt.token is not None else receipt.final_hop.amount_subunits
        if self.total_balance() + token_amount > MAX_WALLET_BALANCE_SUBUNITS:
            raise WalletBalanceCapError("Wallet balance cap would be exceeded")
        self._entries[receipt.token_id] = receipt
        self._spent_token_ids.discard(receipt.token_id)
        self._seen_nonces.update(incoming_nonces)

    def spend(self, token_id: str) -> Receipt:
        """Remove and return a token receipt for outward transfer.

        Parameters: token_id identifies the token to spend.
        Returns: removed Receipt.
        Raises: WalletStateError when token_id is not currently unspent.
        """
        if token_id not in self._entries:
            raise WalletStateError(f"Token {token_id} is not available in this wallet")
        receipt = self._entries.pop(token_id)
        self._spent_token_ids.add(token_id)
        return receipt

    def restore_unspent(self, receipt: Receipt) -> None:
        """Restore a receipt after a failed send attempt.

        Parameters: receipt is the original receipt removed by spend.
        Returns: None.
        Raises: no custom exceptions.
        """
        self._entries[receipt.token_id] = receipt
        self._spent_token_ids.discard(receipt.token_id)

    def total_balance(self) -> int:
        """Return the current UTR balance.

        Parameters: none.
        Returns: integer subunit balance.
        Raises: no custom exceptions.
        """
        return sum(receipt.token.amount_subunits if receipt.token is not None else receipt.final_hop.amount_subunits for receipt in self._entries.values())

    def list_tokens(self) -> list[str]:
        """List unspent token ids.

        Parameters: none.
        Returns: list of token_id strings.
        Raises: no custom exceptions.
        """
        return list(self._entries.keys())

    def get_receipt(self, token_id: str) -> Receipt:
        """Return a receipt without spending it.

        Parameters: token_id identifies the receipt.
        Returns: Receipt.
        Raises: WalletStateError when token_id is absent.
        """
        if token_id not in self._entries:
            raise WalletStateError(f"Token {token_id} is not available in this wallet")
        return self._entries[token_id]

    def save(self, path: Path) -> None:
        """Persist the UTR to JSON.

        Parameters: path is the target file path.
        Returns: None.
        Raises: OSError if writing fails.
        """
        data = {
            "dpc_version": "1.0",
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": {
                "wallet_id": self.wallet_id,
                "entries": {token_id: json.loads(receipt.to_json()) for token_id, receipt in self._entries.items()},
                "spent_token_ids": sorted(self._spent_token_ids),
                "seen_nonces": sorted(self._seen_nonces),
            },
        }
        path.write_text(json.dumps(data, sort_keys=True, separators=JSON_SEPARATORS), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "UnspentTokenRegister":
        """Load a UTR from JSON.

        Parameters: path is the source file path.
        Returns: UnspentTokenRegister.
        Raises: WalletStateError for version mismatch; OSError/json errors for invalid files.
        """
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("dpc_version") != "1.0":
            raise WalletStateError("Unsupported UTR version")
        data = payload["data"]
        utr = cls(data["wallet_id"])
        utr._entries = {token_id: Receipt.from_json(json.dumps(receipt_data, sort_keys=True, separators=JSON_SEPARATORS)) for token_id, receipt_data in data["entries"].items()}
        utr._spent_token_ids = set(data["spent_token_ids"])
        utr._seen_nonces = set(data["seen_nonces"])
        return utr


class DPCWallet:
    """Core DPC wallet with identity key and local UTR.

    Parameters: wallet_id and DPCKeyPair.
    Returns: wallet capable of receiving, sending, and splitting tokens.
    Raises: no custom exceptions at construction.
    """

    def __init__(self, wallet_id: str, keypair: DPCKeyPair) -> None:
        """Create a wallet.

        Parameters: wallet_id is a local label; keypair is the wallet identity.
        Returns: None.
        Raises: no custom exceptions.
        """
        self.wallet_id = wallet_id
        self.keypair = keypair
        self.utr = UnspentTokenRegister(wallet_id)

    def receive_token(self, token: Token, chain: list[TransferRecord]) -> Receipt:
        """Accept a token addressed to this wallet.

        Parameters: token and its full transfer chain.
        Returns: stored Receipt.
        Raises: TokenExpiredError, WalletStateError, ChainIntegrityError, WalletBalanceCapError, DoubleSpendError.
        """
        if token.is_expired():
            raise TokenExpiredError("Token has expired")
        TransferChain(chain).validate_integrity(token)
        if chain[-1].receiver_pubkey_hex != self.keypair.public_key_hex():
            raise WalletStateError("Token not addressed to this wallet")
        receipt = Receipt(token.token_id, int(time.time()), chain[-1], list(chain), False, token)
        self.utr.add_receipt(receipt)
        return receipt

    def send_token(self, token_id: str, receiver_pubkey_hex: str) -> tuple[Token, list[TransferRecord]]:
        """Create a signed outbound transfer.

        Parameters: token_id to spend and receiver public key hex.
        Returns: token and updated transfer chain.
        Raises: WalletStateError, TokenExpiredError, HopLimitExceededError, TransactionValueCapError.
        """
        receipt = self.utr.spend(token_id)
        try:
            token = self._require_token(receipt)
            if token.is_expired():
                raise TokenExpiredError("Token has expired")
            amount = receipt.final_hop.amount_subunits
            if amount > MAX_SINGLE_TX_SUBUNITS:
                raise TransactionValueCapError("Transaction value cap exceeded")
            TransferChain(receipt.full_chain).validate_integrity(token)
            existing_chain = receipt.full_chain
            prior_owners = {record.sender_pubkey_hex for record in existing_chain}
            if receiver_pubkey_hex in prior_owners:
                effective_hop_index = 1
            else:
                effective_hop_index = existing_chain[-1].hop_index + 1
            if effective_hop_index > MAX_OFFLINE_HOPS:
                raise HopLimitExceededError("Offline hop limit exceeded")
            new_record = TransferRecord(
                token_id=token.token_id,
                hop_index=effective_hop_index,
                sender_pubkey_hex=self.keypair.public_key_hex(),
                receiver_pubkey_hex=receiver_pubkey_hex,
                amount_subunits=amount,
                nonce=secrets.token_hex(NONCE_BYTES),
                prev_hash=existing_chain[-1].chain_hash if existing_chain else GENESIS_HASH,
            )
            new_record.sign(self.keypair.private_key_bytes())
            return token, existing_chain + [new_record]
        except DPCError as exc:
            self.utr.restore_unspent(receipt)
            raise exc

    def swap_change(self, token_id: str, amount_to_send: int, receiver_pubkey_hex: str, issuer_pubkey_hex: str) -> tuple[Token, list[TransferRecord], Token, list[TransferRecord]]:
        """Split one token into payment and change tokens for P2P change.

        Parameters: original token id, payment amount, receiver key, and issuer public key label.
        Returns: payment token/chain and change token/chain.
        Raises: InsufficientFundsError or TransactionValueCapError for invalid split values.
        """
        receipt = self.utr.spend(token_id)
        try:
            original = self._require_token(receipt)
            if amount_to_send <= 0 or amount_to_send >= original.amount_subunits:
                raise InsufficientFundsError("Swap requires a positive amount smaller than the token value")
            change_amount = original.amount_subunits - amount_to_send
            if amount_to_send > MAX_SINGLE_TX_SUBUNITS or change_amount > MAX_SINGLE_TX_SUBUNITS:
                raise TransactionValueCapError("Swap output exceeds transaction value cap")
            now = int(time.time())
            payment_token = Token(secrets.token_hex(16), issuer_pubkey_hex, amount_to_send, now, original.ttl_expiry, "")
            change_token = Token(secrets.token_hex(16), issuer_pubkey_hex, change_amount, now, original.ttl_expiry, "")
            payment_token.issuer_signature = self.keypair.sign(payment_token.genesis_payload_bytes()).hex()
            change_token.issuer_signature = self.keypair.sign(change_token.genesis_payload_bytes()).hex()
            payment_chain = [self._make_split_record(payment_token, receiver_pubkey_hex)]
            change_chain = [self._make_split_record(change_token, self.keypair.public_key_hex())]
            return payment_token, payment_chain, change_token, change_chain
        except (InsufficientFundsError, TransactionValueCapError) as exc:
            self.utr.restore_unspent(receipt)
            raise exc

    def get_balance(self) -> int:
        """Return this wallet's integer subunit balance.

        Parameters: none.
        Returns: balance in subunits.
        Raises: no custom exceptions.
        """
        return self.utr.total_balance()

    def get_balance_etb(self) -> str:
        """Return this wallet's balance formatted as ETB.

        Parameters: none.
        Returns: formatted ETB string.
        Raises: no custom exceptions.
        """
        balance = self.get_balance()
        return f"{balance // SUBUNITS_PER_ETB:,}.{balance % SUBUNITS_PER_ETB:02d} ETB"

    def _require_token(self, receipt: Receipt) -> Token:
        if receipt.token is None:
            raise WalletStateError("Receipt does not contain token payload")
        return receipt.token

    def _make_split_record(self, token: Token, receiver_pubkey_hex: str) -> TransferRecord:
        record = TransferRecord(
            token_id=token.token_id,
            hop_index=0,
            sender_pubkey_hex=self.keypair.public_key_hex(),
            receiver_pubkey_hex=receiver_pubkey_hex,
            amount_subunits=token.amount_subunits,
            nonce=secrets.token_hex(NONCE_BYTES),
            prev_hash=GENESIS_HASH,
        )
        record.sign(self.keypair.private_key_bytes())
        return record
