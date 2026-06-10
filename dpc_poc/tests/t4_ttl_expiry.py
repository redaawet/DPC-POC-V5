from __future__ import annotations

from pathlib import Path
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T4: Token TTL Expiry]")
    issuer = Wallet()
    alice = Wallet()
    bob = Wallet()
    token = mint_direct(issuer, alice, 250.0)
    alice.state.unspent_tokens[token.token_id].issued_at = time.time() - (8 * 24 * 3600)
    print("[Alice] Checking token timestamp (8 days old) against TTL (7d)...")
    try:
        BLEChannel(alice, bob).execute_transfer(alice, bob, token.token_id, 250.0)
    except ValueError as exc:
        print("[Alice] ERROR: Token expired (stale offline token). Cannot create payment.")
        return result_line("T4", "expired" in str(exc), "expired token rejected")
    return result_line("T4", False, "expired token was accepted")


if __name__ == "__main__":
    run()
