from __future__ import annotations

from pathlib import Path
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpc.proxy_sync import ProxySync
from dpc.reconciliation import IssuerLedger
from dpc.wallet import Wallet
from helpers import mint_direct, result_line


def run() -> bool:
    print("[TEST T5: Delegated Reconciliation / Proxy Sync]")
    issuer = Wallet()
    device_a = Wallet()
    device_b = Wallet()
    mint_direct(issuer, device_a, 100.0)
    ledger = IssuerLedger()
    proxy = ProxySync(ledger)
    device_a.state.last_sync_timestamp = time.time() - (6 * 24 * 3600)
    heartbeat = device_a.get_sync_heartbeat()
    print("[Device B] Received sync heartbeat from A.")
    result = proxy.relay_heartbeat(heartbeat, relay_wallet=device_b)
    synced_at = proxy.get_effective_last_sync(device_a.pubkey_hex)
    print("[Ledger] Updated A.last_sync to current time.")
    valid = result and abs(time.time() - synced_at) <= 5
    if valid:
        print("[Device A] TTL reset confirmed. Device A tokens remain active.")
    return result_line("T5", valid, "proxy heartbeat reset TTL")


if __name__ == "__main__":
    run()
