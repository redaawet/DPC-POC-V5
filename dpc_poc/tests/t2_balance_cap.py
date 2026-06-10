from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T2: Maximum Wallet Balance Cap]")
    issuer = Wallet()
    alice = Wallet()
    bob = Wallet()
    for _ in range(19):
        mint_direct(issuer, bob, 500.0)
    incoming = mint_direct(issuer, alice, 600.0)
    print(f"[Bob] Current balance: {bob.balance:g}, incoming: 600, cap: 10000")
    if bob.balance != 9500.0:
        return result_line("T2", False, "Bob setup balance was not 9500 ETB")
    try:
        BLEChannel(alice, bob).execute_transfer(alice, bob, incoming.token_id, 600.0)
    except ValueError as exc:
        print("[Bob] ERROR: Rejecting payment - would exceed max wallet balance.")
        return result_line("T2", "max wallet balance" in str(exc), "wallet cap enforced")
    return result_line("T2", False, "over-cap payment was accepted")


if __name__ == "__main__":
    run()
