"""Offline BLE/NFC-like bundle exchange simulator."""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from crypto.session import (
    decrypt_bundle,
    derive_session_key,
    ecdh_shared_secret,
    ed25519_sk_to_x25519_sk,
    encrypt_bundle,
    x25519_public_bytes,
)
from digital_token.poc_models import PaymentBundle
from digital_token.poc_models import Token, Transfer
from protocol.proxy_sync import create_heartbeat, relay_heartbeat
from wallet.offline_wallet import Wallet


@dataclass
class SessionEnvelope:
    """Encrypted transport envelope for a serialized payment bundle."""

    sender_x25519_pk: bytes
    nonce_material: bytes
    nonce: bytes
    ciphertext: bytes


def _transfer_to_dict(transfer: Transfer) -> dict[str, Any]:
    payload = asdict(transfer)
    payload["timestamp"] = transfer.timestamp.isoformat()
    return payload


def _token_to_dict(token: Token) -> dict[str, Any]:
    payload = asdict(token)
    payload["created_at"] = token.created_at.isoformat()
    return payload


def _bundle_to_bytes(bundle: PaymentBundle) -> bytes:
    payload = {
        "bundle_id": bundle.bundle_id,
        "transfers": [_transfer_to_dict(transfer) for transfer in bundle.transfers],
        "tokens": {token_id: _token_to_dict(token) for token_id, token in bundle.tokens.items()},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _transfer_from_dict(payload: dict[str, Any]) -> Transfer:
    data = dict(payload)
    data["timestamp"] = datetime.fromisoformat(data["timestamp"])
    return Transfer(**data)


def _token_from_dict(payload: dict[str, Any]) -> Token:
    data = dict(payload)
    data["created_at"] = datetime.fromisoformat(data["created_at"])
    return Token(**data)


def _bundle_from_bytes(payload: bytes) -> PaymentBundle:
    data = json.loads(payload.decode("utf-8"))
    return PaymentBundle(
        bundle_id=data["bundle_id"],
        transfers=[_transfer_from_dict(item) for item in data["transfers"]],
        tokens={token_id: _token_from_dict(token_payload) for token_id, token_payload in data["tokens"].items()},
    )


def _build_envelope(sender_wallet: Wallet, receiver_wallet: Wallet, bundle: PaymentBundle) -> SessionEnvelope:
    sender_x25519 = ed25519_sk_to_x25519_sk(bytes.fromhex(sender_wallet.private_key_hex))
    receiver_x25519 = ed25519_sk_to_x25519_sk(bytes.fromhex(receiver_wallet.private_key_hex))
    sender_x25519_pk = x25519_public_bytes(sender_x25519)
    receiver_x25519_pk = x25519_public_bytes(receiver_x25519)
    nonce_material = sender_x25519_pk + receiver_x25519_pk
    shared_secret = ecdh_shared_secret(sender_x25519, receiver_x25519_pk)
    session_key = derive_session_key(shared_secret, nonce_material)
    nonce, ciphertext = encrypt_bundle(_bundle_to_bytes(bundle), session_key)
    return SessionEnvelope(sender_x25519_pk, nonce_material, nonce, ciphertext)


def _open_envelope(receiver_wallet: Wallet, envelope: SessionEnvelope) -> PaymentBundle:
    receiver_x25519 = ed25519_sk_to_x25519_sk(bytes.fromhex(receiver_wallet.private_key_hex))
    shared_secret = ecdh_shared_secret(receiver_x25519, envelope.sender_x25519_pk)
    session_key = derive_session_key(shared_secret, envelope.nonce_material)
    return _bundle_from_bytes(decrypt_bundle(envelope.nonce, envelope.ciphertext, session_key))


def encode_envelope(envelope: SessionEnvelope) -> dict[str, str]:
    """Return a JSON-safe view of a session envelope for diagnostics."""
    return {
        "sender_x25519_pk": base64.b64encode(envelope.sender_x25519_pk).decode("ascii"),
        "nonce_material": base64.b64encode(envelope.nonce_material).decode("ascii"),
        "nonce": base64.b64encode(envelope.nonce).decode("ascii"),
        "ciphertext": base64.b64encode(envelope.ciphertext).decode("ascii"),
    }


def send_bundle(sender_wallet: Wallet, receiver_wallet: Wallet, bundle: PaymentBundle, *, encrypt: bool = False) -> list[tuple[str, bool]]:
    """Simulate offline transfer from sender to receiver."""
    transmitted_bundle = _open_envelope(receiver_wallet, _build_envelope(sender_wallet, receiver_wallet, bundle)) if encrypt else bundle
    return receiver_wallet.receive_bundle(transmitted_bundle)


def simulate_proxy_sync(offline_wallet: Wallet, online_wallet: Wallet, reconciliation_server: object) -> dict[str, object]:
    """Relay a signed sync heartbeat from an offline wallet through an online peer."""
    _ = online_wallet
    token_ids = sorted(offline_wallet.utr.keys())
    heartbeat = create_heartbeat(
        bytes.fromhex(offline_wallet.private_key_hex),
        bytes.fromhex(offline_wallet.public_key_hex),
        token_ids,
    )
    return relay_heartbeat(heartbeat, reconciliation_server)
