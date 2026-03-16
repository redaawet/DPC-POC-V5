"""Two-phase transfer protocol simulator over an abstract channel."""

from __future__ import annotations

from dataclasses import dataclass
import json
import uuid

from wallet.wallet import Wallet


@dataclass(frozen=True)
class DiscoveryMessage:
    """Discovery exchange carrying sender/receiver identities and a session id."""

    sender_pk: str
    receiver_pk: str
    session_id: str


@dataclass(frozen=True)
class TransferPayload:
    """Transfer payload sent after discovery negotiation."""

    session_id: str
    nonce: int
    token_json: str
    transfer_signature: str


class Channel:
    """In-memory transport simulator for discovery and transfer phases."""

    def __init__(self) -> None:
        self._discoveries: dict[str, DiscoveryMessage] = {}
        self._payloads: dict[str, TransferPayload] = {}

    def open_session(self, sender_pk: str, receiver_pk: str) -> DiscoveryMessage:
        """Phase 1: exchange public keys and return a new session."""
        session = DiscoveryMessage(
            sender_pk=sender_pk,
            receiver_pk=receiver_pk,
            session_id=str(uuid.uuid4()),
        )
        self._discoveries[session.session_id] = session
        return session

    def send_transfer_payload(self, payload: TransferPayload) -> None:
        """Phase 2: store transfer payload for an already opened session."""
        discovery = self._discoveries.get(payload.session_id)
        if discovery is None:
            raise ValueError("unknown session")
        if payload.nonce <= 0:
            raise ValueError("nonce must be positive")
        self._payloads[payload.session_id] = payload

    def receive_transfer_payload(self, session_id: str, receiver_pk: str) -> TransferPayload:
        """Receive transfer payload for a receiver bound to the session."""
        discovery = self._discoveries.get(session_id)
        if discovery is None:
            raise ValueError("unknown session")
        if discovery.receiver_pk != receiver_pk:
            raise ValueError("receiver public key mismatch")
        payload = self._payloads.get(session_id)
        if payload is None:
            raise ValueError("payload not available")
        return payload


def build_payload_from_wallet_send(session_id: str, nonce: int, token_json: str) -> TransferPayload:
    """Build protocol payload from a wallet `send_token` JSON blob."""
    data = json.loads(token_json)
    transfer_chain = data.get("transfer_chain", [])
    if not transfer_chain:
        raise ValueError("token payload missing transfer chain")
    transfer_signature = transfer_chain[-1]["signature"]
    return TransferPayload(
        session_id=session_id,
        nonce=nonce,
        token_json=token_json,
        transfer_signature=transfer_signature,
    )


def transfer_over_channel(sender_wallet: Wallet, receiver_wallet: Wallet, channel: Channel, nonce: int = 1) -> bool:
    """Execute discovery + transfer phases between two wallets over a channel."""
    discovery = channel.open_session(sender_wallet.owner_pk, receiver_wallet.owner_pk)
    token_json = sender_wallet.send_token(receiver_pk=discovery.receiver_pk)
    payload = build_payload_from_wallet_send(discovery.session_id, nonce=nonce, token_json=token_json)
    channel.send_transfer_payload(payload)
    inbound = channel.receive_transfer_payload(discovery.session_id, receiver_wallet.owner_pk)
    return receiver_wallet.receive_token(inbound.token_json)
