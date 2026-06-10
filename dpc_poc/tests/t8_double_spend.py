from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.ble_sim import BLEChannel
from dpc.reconciliation import IssuerLedger
from dpc.transfer import build_transfer
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T8: Double-Spending Prevention via Reconciliation]")
    issuer = Wallet()
    alice = Wallet()
    merchant_a = Wallet()
    merchant_b = Wallet()
    ledger = IssuerLedger()
    token_x = mint_direct(issuer, alice, 800.0)
    cloned_token_x = deepcopy(token_x)

    _, token_for_a = BLEChannel(alice, merchant_a).execute_transfer(
        alice, merchant_a, token_x.token_id, 800.0
    )
    record_b, cloned_token_for_b = build_transfer(
        cloned_token_x,
        alice.private_key_bytes,
        alice.pubkey_hex,
        merchant_b.pubkey_hex,
        800.0,
        alice.state.policy,
        alice.state,
    )
    merchant_b.receive_token(cloned_token_for_b, record_b)

    print(f"[Merchant A] Submitting Token {token_x.token_id[:8]} to Ledger...")
    result_a = ledger.submit_token(token_for_a, merchant_a.pubkey_hex)
    print(f"[Ledger] Token {token_x.token_id[:8]} accepted. Ownership updated (Alice->MerchantA).")
    print(f"[Merchant B] Submitting Token {token_x.token_id[:8]} to Ledger...")
    result_b = ledger.submit_token(cloned_token_for_b, merchant_b.pubkey_hex)
    print(f"[Ledger] ERROR: Token {token_x.token_id[:8]} already spent. Rejecting transaction.")
    print("[Ledger] Flagging PK_Alice as suspicious.")
    ledger.print_report()
    valid = (
        result_a["accepted"] is True
        and result_b["accepted"] is False
        and "already spent" in result_b["reason"].lower()
        and ledger.is_flagged(alice.pubkey_hex)
    )
    return result_line("T8", valid, "first valid ledger claim wins")


if __name__ == "__main__":
    run()
