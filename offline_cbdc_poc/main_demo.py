"""Demonstration scenario for offline CBDC token payments."""
from __future__ import annotations

from .crypto_utils import generate_keypair
from .issuer import Issuer
from .network_simulator import send_bundle
from .policy import PolicyConfig
from .reconciliation_server import ReconciliationServer
from .wallet import Wallet


def print_wallet_state(label: str, wallet: Wallet) -> None:
    print(f"{label} balance: {wallet.balance()}")
    print(
        f"{label} UTR tokens: "
        f"{[(t.token_id[:8], t.value, t.hop_count) for t in wallet.snapshot_tokens()]}"
    )


def main() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=100, MAX_TOKEN_HOPS=5, MAX_WALLET_BALANCE=1000, TOKEN_EXPIRY_SECONDS=3600)

    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    print("1) Issuer keypair generated")

    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()

    alice = Wallet("Alice", alice_sk, alice_pk, policy)
    bob = Wallet("Bob", bob_sk, bob_pk, policy)
    print("2) Wallets created: Alice and Bob")

    for value in (10, 10, 10):
        alice.receive_token(issuer.mint_token(owner_pk=alice_pk, value=value))
    print("3) Issuer minted [10,10,10] for Alice")
    print_wallet_state("Alice", alice)
    print_wallet_state("Bob", bob)

    bundle = alice.create_payment(receiver_pk=bob_pk, amount=25)
    print(f"\n4) Alice created offline payment bundle {bundle.bundle_id}")
    print(f"Bundle transfers: {[t.transfer_id[:8] for t in bundle.transfers]}")

    rx_results = send_bundle(alice, bob, bundle)
    print("5) Bob receive results:", rx_results)
    print_wallet_state("Alice", alice)
    print_wallet_state("Bob", bob)

    reconciler = ReconciliationServer(issuer)
    settlement = reconciler.process_bundle(bundle)
    print("\n6) Reconciliation results:")
    for rec in settlement:
        print(vars(rec))

    print("\n7) Ledger snapshot:")
    for token_id, rec in reconciler.ledger.items():
        print(token_id[:8], rec.status)

    print("\n8) Double-spend demonstration (re-submit same bundle):")
    second_settlement = reconciler.process_bundle(bundle)
    for rec in second_settlement:
        print(vars(rec))


if __name__ == "__main__":
    main()
