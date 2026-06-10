from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T1: Maximum Offline Hops Enforcement]")
    issuer = Wallet()
    alice = Wallet()
    bob = Wallet()
    token = mint_direct(issuer, alice, 500.0)
    alice.state.unspent_tokens[token.token_id].hop_count = 6
    print("[Alice] Simulated token hop count set to 6.")

    channel = BLEChannel(alice, bob)
    _, token_for_bob = channel.execute_transfer(alice, bob, token.token_id, 500.0)
    print(f"[Bob] Token nonce updated to {token_for_bob.hop_count}.")
    if token_for_bob.hop_count != 7:
        return result_line("T1", False, "7th transfer did not set hop count to 7")

    try:
        BLEChannel(bob, alice).execute_transfer(bob, alice, token.token_id, 500.0)
    except ValueError as exc:
        print(f"[Error] {exc} - transfer rejected as expected.")
        return result_line("T1", "Hop limit" in str(exc), "hop limit enforced")
    return result_line("T1", False, "8th transfer was not rejected")


if __name__ == "__main__":
    run()
