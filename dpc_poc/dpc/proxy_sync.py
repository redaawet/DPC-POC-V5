"""Delegated proxy synchronization for offline devices.

Allows online peers to relay signed heartbeats to the issuer ledger,
resetting TTL countdown without device going online.
"""
from __future__ import annotations

import time

from .crypto import ed25519_verify, hex_to_pubkey_bytes
from .models import PolicyConfig, SyncHeartbeat, Token
from .reconciliation import IssuerLedger


class ProxySync:
    """Relays heartbeats from offline devices to issuer ledger."""

    def __init__(self, issuer_ledger: IssuerLedger):
        """Initialize with reference to issuer ledger."""
        self.ledger = issuer_ledger
        self.sync_registry: dict[str, float] = {}

    def relay_heartbeat(self, heartbeat: SyncHeartbeat) -> bool:
        """
        Relay a signed heartbeat to the ledger.
        1. Verify device's Ed25519 signature (prevents relay tampering)
        2. Update sync registry with current timestamp
        Returns True if valid and updated, False if signature invalid.
        """
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
        """Get most recent sync timestamp for wallet (0 if never synced)."""
        return self.sync_registry.get(wallet_pubkey_hex, 0)

    def is_token_valid(self, token: Token, wallet_pubkey_hex: str, policy: PolicyConfig) -> bool:
        """
        Check if token is valid considering both issuance time and sync TTL:
        (now - issued_at) < ttl AND (now - last_sync_time) < ttl
        """
        now = time.time()
        return (
            now - token.issued_at < policy.token_ttl_seconds
            and now - self.get_effective_last_sync(wallet_pubkey_hex) < policy.token_ttl_seconds
        )
