"""Simulated Bluetooth Low Energy channel for DPC offline payments.

Encrypts payloads with ChaCha20-Poly1305 using X25519-derived session keys.
No actual BLE hardware; all communication is simulated via Python function calls.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import os

from .crypto import chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, derive_session_key, hex_to_pubkey_bytes
from .models import Token, TransferRecord
from .wallet import Wallet


class BLEChannel:
    """
    Simulates a BLE link between two wallets with optional session encryption.
    Derives shared key via X25519 ECDH, encrypts payloads with ChaCha20-Poly1305.
    """

    def __init__(self, wallet_a: Wallet, wallet_b: Wallet, encrypt: bool = True):
        """
        Initialize BLE channel between two wallets.
        If encrypt=True, derive session key from X25519 ECDH.
        """
        self.wallet_a = wallet_a
        self.wallet_b = wallet_b
        self.encrypt = encrypt
        self.previous_packet_size: int | None = None
        self.session_key: bytes | None = None
        self.session_nonce_12: bytes | None = None
        if encrypt:
            self.session_nonce_12 = os.urandom(12)
            self.session_key = derive_session_key(
                wallet_a.private_key_bytes,
                hex_to_pubkey_bytes(wallet_b.pubkey_hex),
                self.session_nonce_12,
            )

    def transmit(self, sender_name: str, receiver_name: str, packet_data) -> bytes:
        """
        Transmit packet data over BLE while logging packet size and growth.
        """
        if isinstance(packet_data, bytes):
            packet_bytes = packet_data
        elif isinstance(packet_data, str):
            packet_bytes = packet_data.encode("utf-8")
        else:
            packet_bytes = json.dumps(packet_data, separators=(",", ":")).encode("utf-8")

        current_size = len(packet_bytes)
        if self.previous_packet_size is None:
            growth_str = " | Base Packet Size"
        else:
            constant = current_size - self.previous_packet_size
            growth_str = f" | Linear Increase Constant: +{constant} bytes" if constant > 0 else ""

        print(f"[BLE] {sender_name}->{receiver_name} | {current_size} bytes transmitted{growth_str}")
        self.previous_packet_size = current_size

        if not self.encrypt:
            return packet_bytes
        if self.session_key is None or self.session_nonce_12 is None:
            raise RuntimeError("Session key not initialized")
        encrypted = chacha20_poly1305_encrypt(self.session_key, self.session_nonce_12, packet_bytes)
        return chacha20_poly1305_decrypt(self.session_key, self.session_nonce_12, encrypted)

    def execute_transfer(
        self,
        sender_wallet: Wallet,
        recipient_wallet: Wallet,
        token_id: str,
        amount: float,
    ) -> tuple[TransferRecord, Token]:
        """
        Full BLE payment handshake:
        1. Sender creates transfer and new token
        2. Serialize and transmit
        3. Recipient receives, deserializes, and validates
        """
        record, new_token = sender_wallet.send_token(token_id, recipient_wallet.pubkey_hex, amount)
        payload = json.dumps(
            {"record": asdict(record), "token": asdict(new_token)},
            separators=(",", ":"),
        ).encode("utf-8")
        sender_name = sender_wallet.pubkey_hex[:8]
        receiver_name = recipient_wallet.pubkey_hex[:8]
        received = self.transmit(sender_name, receiver_name, payload)
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
        """
        Swap protocol for peer-to-peer change generation:
        1. Payer sends full token denomination to payee
        2. Payee sends back change token
        3. Atomicity ensured by same BLE session
        """
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
