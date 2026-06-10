from __future__ import annotations

from dataclasses import replace
import time
import secrets

from .crypto import ed25519_pubkey_to_hex, ed25519_sign, ed25519_verify, generate_ed25519_keypair, hex_to_pubkey_bytes
from .models import PolicyConfig, SyncHeartbeat, Token, TransferRecord, WalletState
from .transfer import build_transfer, verify_transfer_chain


def token_signature_message(token_id: str, issuer_pubkey_hex: str, issued_at: float, denomination: float) -> bytes:
    return f"{token_id}{issuer_pubkey_hex}{issued_at}{denomination}".encode("utf-8")


class Wallet:
    def __init__(self, policy: PolicyConfig | None = None):
        self.private_key_bytes, public_key_bytes = generate_ed25519_keypair()
        self._pubkey_hex = ed25519_pubkey_to_hex(public_key_bytes)
        self.state = WalletState(
            owner_pubkey_hex=self._pubkey_hex,
            policy=policy or PolicyConfig(),
        )

    @property
    def pubkey_hex(self) -> str:
        return self._pubkey_hex

    @property
    def balance(self) -> float:
        return sum(token.denomination for token in self.state.unspent_tokens.values())

    def _verify_issuer_signature(self, token: Token) -> bool:
        return ed25519_verify(
            hex_to_pubkey_bytes(token.issuer_pubkey_hex),
            token_signature_message(
                token.token_id,
                token.issuer_pubkey_hex,
                token.issued_at,
                token.denomination,
            ),
            bytes.fromhex(token.issuer_signature_hex),
        )

    def receive_token(self, token: Token, transfer_record: TransferRecord) -> None:
        if not self._verify_issuer_signature(token):
            raise ValueError("Invalid issuer signature")
        if not verify_transfer_chain(token, transfer_record):
            raise ValueError("Invalid transfer chain")
        if (token.token_id, transfer_record.nonce_hex) in self.state.spent_nonces:
            raise ValueError("Replay detected")
        if self.balance + token.denomination > self.state.policy.max_wallet_balance_etb:
            raise ValueError("Exceeds max wallet balance")
        if token.owner_pubkey_hex != self.pubkey_hex:
            raise ValueError("Token owner does not match wallet")
        if self.pubkey_hex in token.transfer_history[:-1]:
            token = replace(token, hop_count=0, chain_hash="")
        self.state.spent_nonces.add((token.token_id, transfer_record.nonce_hex))
        self.state.unspent_tokens[token.token_id] = token

    def send_token(self, token_id: str, recipient_pubkey_hex: str, amount: float) -> tuple[TransferRecord, Token]:
        token = self.state.unspent_tokens.get(token_id)
        if token is None:
            raise ValueError("Token not found in wallet")
        if self.pubkey_hex in token.transfer_history[:-1]:
            print("Detected own key in history. Resetting hop count to 0.")
            token = replace(token, hop_count=0, chain_hash="")
            self.state.unspent_tokens[token_id] = token
        record, new_token = build_transfer(
            token,
            self.private_key_bytes,
            self.pubkey_hex,
            recipient_pubkey_hex,
            amount,
            self.state.policy,
            self.state,
        )
        del self.state.unspent_tokens[token_id]
        self.state.spent_nonces.add((token_id, record.nonce_hex))
        return record, new_token

    def get_token_for_swap(self, amount: float) -> Token | None:
        candidates = [token for token in self.state.unspent_tokens.values() if token.denomination >= amount]
        return min(candidates, key=lambda token: token.denomination) if candidates else None

    def issue_token(self, denomination: float) -> Token:
        token_id = secrets.token_hex(16)
        issued_at = time.time()
        signature = ed25519_sign(
            self.private_key_bytes,
            token_signature_message(token_id, self.pubkey_hex, issued_at, denomination),
        ).hex()
        token = Token(
            token_id=token_id,
            denomination=denomination,
            issuer_pubkey_hex=self.pubkey_hex,
            issued_at=issued_at,
            issuer_signature_hex=signature,
            owner_pubkey_hex=self.pubkey_hex,
            transfer_history=[self.pubkey_hex],
        )
        self.state.unspent_tokens[token_id] = token
        return token

    def deposit_to_issuer(self, token_id: str) -> Token:
        try:
            return self.state.unspent_tokens.pop(token_id)
        except KeyError as exc:
            raise ValueError("Token not found in wallet") from exc

    def get_sync_heartbeat(self) -> SyncHeartbeat:
        token_ids = sorted(self.state.unspent_tokens)
        message = f"{self.pubkey_hex}{self.state.last_sync_timestamp}{''.join(token_ids)}".encode("utf-8")
        return SyncHeartbeat(
            wallet_pubkey_hex=self.pubkey_hex,
            last_sync_timestamp=self.state.last_sync_timestamp,
            token_ids=token_ids,
            signature_hex=ed25519_sign(self.private_key_bytes, message).hex(),
        )
