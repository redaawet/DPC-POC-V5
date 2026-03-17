"""Offline BLE/NFC-like bundle exchange simulator."""
from __future__ import annotations

from digital_token.poc_models import PaymentBundle
from wallet.offline_wallet import Wallet


def send_bundle(sender_wallet: Wallet, receiver_wallet: Wallet, bundle: PaymentBundle) -> list[tuple[str, bool]]:
    """Simulate offline transfer from sender to receiver."""
    _ = sender_wallet
    return receiver_wallet.receive_bundle(bundle)
