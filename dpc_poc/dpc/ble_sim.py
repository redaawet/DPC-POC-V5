from __future__ import annotations

from dataclasses import asdict
import json
import os

from .crypto import chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, derive_session_key, hex_to_pubkey_bytes
from .models import Token, TransferRecord
from .wallet import Wallet


class BLEChannel:
    def __init__(self, wallet_a: Wallet, wallet_b: Wallet, encrypt: bool = True):
        self.wallet_a = wallet_a
        self.wallet_b = wallet_b
        self.encrypt = encrypt
        self.session_key: bytes | None = None
        self.session_nonce_12: bytes | None = None
        if encrypt:
            self.session_nonce_12 = os.urandom(12)
            self.session_key = derive_session_key(
                wallet_a.private_key_bytes,
                hex_to_pubkey_bytes(wallet_b.pubkey_hex),
                self.session_nonce_12,
            )

    def transmit(self, payload_bytes: bytes, direction: str = "A->B") -> bytes:
        print(f"[BLE] {direction} | {len(payload_bytes)} bytes transmitted")
        if not self.encrypt:
            return payload_bytes
        assert self.session_key is not None
        assert self.session_nonce_12 is not None
        encrypted = chacha20_poly1305_encrypt(self.session_key, self.session_nonce_12, payload_bytes)
        return chacha20_poly1305_decrypt(self.session_key, self.session_nonce_12, encrypted)

    def execute_transfer(
        self,
        sender_wallet: Wallet,
        recipient_wallet: Wallet,
        token_id: str,
        amount: float,
    ) -> tuple[TransferRecord, Token]:
        record, new_token = sender_wallet.send_token(token_id, recipient_wallet.pubkey_hex, amount)
        payload = json.dumps(
            {"record": asdict(record), "token": asdict(new_token)},
            separators=(",", ":"),
        ).encode("utf-8")
        direction = "A->B" if sender_wallet is self.wallet_a else "B->A"
        received = self.transmit(payload, direction=direction)
        data = json.loads(received.decode("utf-8"))
        received_record = TransferRecord(**data["record"])
        received_token = Token(**data["token"])
        recipient_wallet.receive_token(received_token, received_record)
        print(
            f"[BLE] {sender_wallet.pubkey_hex[:8]} -> {recipient_wallet.pubkey_hex[:8]} "
            f"| {amount:g} ETB | hop_count={received_token.hop_count}"
        )
        return received_record, received_token

    def execute_swap(
        self,
        payer_wallet: Wallet,
        payee_wallet: Wallet,
        payer_token_id: str,
        owed_amount: float,
    ) -> None:
        payer_token = payer_wallet.state.unspent_tokens[payer_token_id]
        change_amount = payer_token.denomination - owed_amount
        change_token = payee_wallet.get_token_for_swap(change_amount)
        if change_amount < 0:
            raise ValueError("Insufficient token value")
        if change_amount > 0 and change_token is None:
            raise ValueError("Insufficient change tokens for swap")
        self.execute_transfer(payer_wallet, payee_wallet, payer_token_id, payer_token.denomination)
        if change_token is not None and change_amount > 0:
            self.execute_transfer(payee_wallet, payer_wallet, change_token.token_id, change_token.denomination)
        print(f"[BLE] Swap complete. Payer net: -{owed_amount:g} ETB, Payee net: +{owed_amount:g} ETB")
