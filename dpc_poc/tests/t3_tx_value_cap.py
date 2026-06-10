from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T3: Single-Transaction Value Cap]")
    issuer = Wallet()
    alice = Wallet()
    bob = Wallet()
    token = mint_direct(issuer, alice, 2000.0)
    try:
        BLEChannel(alice, bob).execute_transfer(alice, bob, token.token_id, 1200.0)
    except ValueError as exc:
        print(f"[Alice] ERROR: {exc}")
        return result_line("T3", "offline pocket cash limits" in str(exc), "transaction value cap enforced")
    return result_line("T3", False, "over-cap transfer was accepted")


if __name__ == "__main__":
    run()
