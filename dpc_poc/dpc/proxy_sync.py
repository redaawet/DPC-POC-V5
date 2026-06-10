from __future__ import annotations

import time

from .crypto import ed25519_verify, hex_to_pubkey_bytes
from .models import PolicyConfig, SyncHeartbeat, Token
from .reconciliation import IssuerLedger
from .wallet import Wallet


class ProxySync:
    def __init__(self, issuer_ledger: IssuerLedger):
        self.ledger = issuer_ledger
        self.sync_registry: dict[str, float] = {}

    def relay_heartbeat(self, heartbeat: SyncHeartbeat, relay_wallet: Wallet) -> bool:
        del relay_wallet
        message = (
            f"{heartbeat.wallet_pubkey_hex}{heartbeat.last_sync_timestamp}"
            f"{''.join(sorted(heartbeat.token_ids))}"
        ).encode("utf-8")
        valid = ed25519_verify(
            hex_to_pubkey_bytes(heartbeat.wallet_pubkey_hex),
            message,
            bytes.fromhex(heartbeat.signature_hex),
        )
        if not valid:
            return False
        timestamp = time.time()
        self.sync_registry[heartbeat.wallet_pubkey_hex] = timestamp
        print(f"[Ledger] Updated {heartbeat.wallet_pubkey_hex[:8]}...last_sync to {timestamp}")
        return True

    def get_effective_last_sync(self, wallet_pubkey_hex: str) -> float:
        return self.sync_registry.get(wallet_pubkey_hex, 0)

    def is_token_valid(self, token: Token, wallet_pubkey_hex: str, policy: PolicyConfig) -> bool:
        now = time.time()
        return (
            now - token.issued_at < policy.token_ttl_seconds
            and now - self.get_effective_last_sync(wallet_pubkey_hex) < policy.token_ttl_seconds
        )
