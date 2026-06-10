from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T7: Peer-to-Peer Change Generation - Swap Protocol]")
    issuer = Wallet()
    alice = Wallet()
    bob = Wallet()
    token_20 = mint_direct(issuer, alice, 20.0)
    mint_direct(issuer, bob, 5.0)
    BLEChannel(alice, bob).execute_swap(alice, bob, token_20.token_id, 15.0)
    valid = alice.balance == 5.0 and bob.balance == 20.0
    print(f"[Alice] Balance: {alice.balance:g} ETB")
    print(f"[Bob] Balance: {bob.balance:g} ETB")
    return result_line("T7", valid, "swap generated correct change")


if __name__ == "__main__":
    run()
