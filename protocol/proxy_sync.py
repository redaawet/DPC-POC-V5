"""Signed proxy synchronisation heartbeat relay for offline wallets."""

from __future__ import annotations

import dataclasses
import time

from crypto.crypto_utils import sign, verify
from protocol.policy import PolicyConfig


@dataclasses.dataclass
class SyncHeartbeat:
    """
    Compact signed struct that the offline wallet gives to a relay peer.
    The relay peer cannot tamper with it without invalidating the signature.
    Fields serialised for signing: wallet_pk + token_ids_csv + str(timestamp)
    """

    wallet_pk: bytes
    token_ids: list[str]
    timestamp: float
    signature: bytes


def _heartbeat_payload(wallet_pk: bytes, token_ids: list[str], timestamp: float) -> bytes:
    ordered_ids = ",".join(sorted(token_ids))
    return wallet_pk.hex().encode("ascii") + b"|" + ordered_ids.encode("utf-8") + b"|" + repr(timestamp).encode("ascii")


def create_heartbeat(wallet_sk: bytes, wallet_pk: bytes, token_ids: list[str]) -> SyncHeartbeat:
    """Wallet owner creates and signs a heartbeat."""
    timestamp = time.time()
    payload = _heartbeat_payload(wallet_pk, token_ids, timestamp)
    signature = bytes.fromhex(sign(payload, wallet_sk.hex()))
    return SyncHeartbeat(wallet_pk=wallet_pk, token_ids=list(token_ids), timestamp=timestamp, signature=signature)


def verify_heartbeat(hb: SyncHeartbeat) -> bool:
    """Relay peer or ledger verifies the heartbeat before forwarding/applying."""
    payload = _heartbeat_payload(hb.wallet_pk, hb.token_ids, hb.timestamp)
    return verify(payload, hb.signature.hex(), hb.wallet_pk.hex())


def relay_heartbeat(hb: SyncHeartbeat, reconciliation_server: object) -> dict[str, object]:
    """
    Verify and relay a heartbeat to the reconciliation server.

    Returns {'status': 'ok'|'invalid_signature'|'expired_heartbeat',
             'refreshed_tokens': [...]}.
    """
    if not verify_heartbeat(hb):
        return {"status": "invalid_signature", "refreshed_tokens": []}
    policy = getattr(reconciliation_server, "policy", PolicyConfig())
    now_fn = getattr(reconciliation_server, "now_fn", None)
    now = now_fn().timestamp() if now_fn is not None else time.time()
    if now - hb.timestamp > policy.TOKEN_EXPIRY_SECONDS:
        return {"status": "expired_heartbeat", "refreshed_tokens": []}
    refreshed = reconciliation_server.apply_sync_heartbeat(hb)
    return {"status": "ok", "refreshed_tokens": refreshed}
