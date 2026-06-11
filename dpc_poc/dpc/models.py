"""Data models for DPC tokens, wallets, and transfer records."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
import time


@dataclass
class PolicyConfig:
    """Policy limits enforced offline."""
    max_offline_hops: int = 7
    max_wallet_balance_etb: float = 10_000.0
    max_transaction_value_etb: float = 1_000.0
    token_ttl_seconds: int = 604_800


@dataclass
class Token:
    token_id: str
    denomination: float
    issuer_pubkey_hex: str
    issued_at: float
    issuer_signature_hex: str
    owner_pubkey_hex: str
    hop_count: int = 0
    transfer_history: List[str] = field(default_factory=list)
    chain_hash: str = ""


@dataclass
class TransferRecord:
    token_id: str
    prev_owner_pubkey_hex: str
    next_owner_pubkey_hex: str
    amount: float
    nonce_hex: str
    chain_hash: str
    signature_hex: str
    timestamp: float


@dataclass
class SyncHeartbeat:
    wallet_pubkey_hex: str
    last_sync_timestamp: float
    token_ids: List[str]
    signature_hex: str


@dataclass
class WalletState:
    owner_pubkey_hex: str
    unspent_tokens: dict[str, Token] = field(default_factory=dict)
    spent_nonces: set[tuple[str, str]] = field(default_factory=set)
    last_sync_timestamp: float = field(default_factory=time.time)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
