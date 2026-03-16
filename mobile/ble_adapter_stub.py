"""BLE adapter stub used by tests to simulate mobile transport handshakes."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


@dataclass
class BleAdapterStub:
    """In-memory BLE adapter stub with connect/send/receive primitives."""

    device_id: str
    _peers: dict[str, "BleAdapterStub"] = field(default_factory=dict)
    _connected_peer: str | None = None
    _inbox: deque[str] = field(default_factory=deque)

    def register_peer(self, peer: "BleAdapterStub") -> None:
        """Register a peer adapter so `connect` can discover it."""
        self._peers[peer.device_id] = peer

    def connect(self, peer_device_id: str) -> bool:
        """Connect to a known peer device id."""
        if peer_device_id not in self._peers:
            return False
        self._connected_peer = peer_device_id
        return True

    def send(self, payload: str) -> None:
        """Send a payload to the currently connected peer."""
        if self._connected_peer is None:
            raise ValueError("no connected peer")
        peer = self._peers[self._connected_peer]
        peer._inbox.append(payload)

    def receive(self) -> str | None:
        """Receive next queued payload, if any."""
        if not self._inbox:
            return None
        return self._inbox.popleft()
