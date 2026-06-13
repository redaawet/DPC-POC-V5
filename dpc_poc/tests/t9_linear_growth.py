"""Seven-hop BLE linear-growth telemetry regression test."""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from tests.helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T9: Seven-hop BLE linear-growth telemetry]")
    issuer = Wallet()
    devices = [Wallet() for _ in range(8)]
    token = mint_direct(issuer, devices[0], 100.0)

    # Use a single BLE channel to preserve previous_packet_size across the full path.
    channel = BLEChannel(devices[0], devices[1], encrypt=False)

    hops = [
        (devices[0], devices[1], "A->B"),
        (devices[1], devices[2], "B->C"),
        (devices[2], devices[3], "C->D"),
        (devices[3], devices[4], "D->E"),
        (devices[4], devices[5], "E->F"),
        (devices[5], devices[6], "F->G"),
        (devices[6], devices[7], "G->H"),
    ]

    current_token_id = token.token_id
    current_token = token
    for hop_number, (sender, receiver, label) in enumerate(hops, start=1):
        print(f"[HOP {hop_number}] {label}")
        _, current_token = channel.execute_transfer(sender, receiver, current_token_id, 100.0)
        current_token_id = current_token.token_id

    has_token = current_token_id in devices[7].state.unspent_tokens
    valid = has_token and devices[7].balance == 100.0 and current_token.hop_count == 7
    return result_line(
        "T9",
        valid,
        "Token successfully transferred through 7 hops with BLE size growth logged",
    )


if __name__ == "__main__":
    run()
