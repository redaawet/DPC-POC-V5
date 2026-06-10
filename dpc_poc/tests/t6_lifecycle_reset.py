from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T6: Token Lifecycle Reset on Return]")
    issuer = Wallet()
    alice = Wallet()
    bob = Wallet()
    carol = Wallet()
    token = mint_direct(issuer, alice, 500.0)
    BLEChannel(alice, bob).execute_transfer(alice, bob, token.token_id, 500.0)
    BLEChannel(bob, carol).execute_transfer(bob, carol, token.token_id, 500.0)
    print("[A] Token history: [A, B, C]. Detected my key at root. Resetting nonce to 0.")
    BLEChannel(carol, alice).execute_transfer(carol, alice, token.token_id, 500.0)
    returned = alice.state.unspent_tokens[token.token_id]
    if returned.hop_count == 0:
        print("[A] Accepted token as fresh cash.")
    return result_line("T6", returned.hop_count == 0, "lifecycle reset applied on return")


if __name__ == "__main__":
    run()
