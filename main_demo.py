"""Demonstration scenario for offline CBDC token payments."""
from __future__ import annotations

from crypto.crypto_utils import generate_keypair
from issuer.issuer import Issuer
from issuer.reconciliation_server import ReconciliationServer
from protocol.policy import PolicyConfig
from wallet.offline_wallet import Wallet


def print_wallet_state(label: str, wallet: Wallet) -> None:
    print(f"{label} balance: {wallet.balance()}")
    print(
        f"{label} UTR tokens: "
        f"{[(t.token_id[:8], t.value, t.hop_count, t.last_transfer_id[:8] if t.last_transfer_id else None) for t in wallet.snapshot_tokens()]}"
    )


def print_receive_results(step: str, results: list[tuple[str, bool, str]]) -> None:
    print(step)
    for transfer_id, ok, reason in results:
        status = "ACCEPTED" if ok else "REJECTED"
        print(f"  transfer={transfer_id[:8]} status={status} reason={reason}")


def main() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=100, MAX_HOPS=3, MAX_BALANCE=50, TOKEN_EXPIRY_SECONDS=3600)

    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    print("1) Issuer keypair generated")

    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()
    carol_sk, carol_pk = generate_keypair()
    dave_sk, dave_pk = generate_keypair()
    eve_sk, eve_pk = generate_keypair()
    frank_sk, frank_pk = generate_keypair()

    alice = Wallet("Alice", alice_sk, alice_pk, policy)
    bob = Wallet("Bob", bob_sk, bob_pk, policy)
    carol = Wallet("Carol", carol_sk, carol_pk, policy)
    dave = Wallet("Dave", dave_sk, dave_pk, policy)
    eve = Wallet("Eve", eve_sk, eve_pk, policy)
    frank = Wallet("Frank", frank_sk, frank_pk, policy)
    print("2) Wallets created: Alice, Bob, Carol, Dave, Eve, Frank")

    for value in (10, 10, 30):
        alice.receive_token(issuer.mint_token(owner_pk=alice_pk, value=value))
    print("3) Issuer minted [10,10,30] for Alice")
    print_wallet_state("Alice", alice)
    print_wallet_state("Bob", bob)

    bundle_ab = alice.create_payment(receiver_pk=bob_pk, amount=10)
    print(f"\n4) Alice -> Bob bundle {bundle_ab.bundle_id}")
    print(f"Transfers (hop_count): {[(t.transfer_id[:8], t.hop_count) for t in bundle_ab.transfers]}")
    rx_results = bob.receive_bundle_with_reasons(bundle_ab)
    print_receive_results("Receive results:", rx_results)
    print_wallet_state("Alice", alice)
    print_wallet_state("Bob", bob)

    bundle_bc = bob.create_payment(receiver_pk=carol_pk, amount=10)
    print(f"\n5) Bob -> Carol bundle {bundle_bc.bundle_id}")
    print(f"Transfers (hop_count): {[(t.transfer_id[:8], t.hop_count) for t in bundle_bc.transfers]}")
    rx_results = carol.receive_bundle_with_reasons(bundle_bc)
    print_receive_results("Receive results:", rx_results)
    print_wallet_state("Bob", bob)
    print_wallet_state("Carol", carol)

    bundle_cd = carol.create_payment(receiver_pk=dave_pk, amount=10)
    print(f"\n6) Carol -> Dave bundle {bundle_cd.bundle_id}")
    print(f"Transfers (hop_count): {[(t.transfer_id[:8], t.hop_count) for t in bundle_cd.transfers]}")
    rx_results = dave.receive_bundle_with_reasons(bundle_cd)
    print_receive_results("Receive results:", rx_results)
    print_wallet_state("Carol", carol)
    print_wallet_state("Dave", dave)

    # Additional path to ensure Bob owns a token at hop_count=3.
    bundle_ab_second = alice.create_payment(receiver_pk=bob_pk, amount=10)
    bob.receive_bundle(bundle_ab_second)
    bundle_bc_second = bob.create_payment(receiver_pk=carol_pk, amount=10)
    carol.receive_bundle(bundle_bc_second)
    bundle_cb = carol.create_payment(receiver_pk=bob_pk, amount=10)
    bob.receive_bundle(bundle_cb)
    print("\n7) Bob receives token back at hop_count=3")
    print_wallet_state("Bob", bob)

    bundle_be = bob.create_payment(receiver_pk=eve_pk, amount=10)
    print(f"\n8) Bob -> Eve after max hops reached bundle {bundle_be.bundle_id}")
    print(f"Transfers (hop_count): {[(t.transfer_id[:8], t.hop_count) for t in bundle_be.transfers]}")
    hop_reject = eve.receive_bundle_with_reasons(bundle_be)
    print_receive_results("Receive results:", hop_reject)
    print_wallet_state("Bob", bob)
    print_wallet_state("Eve", eve)

    print("\n9) Wallet overflow attempt (expect REJECTION):")
    frank.receive_token(issuer.mint_token(owner_pk=frank_pk, value=25))
    overflow_bundle = alice.create_payment(receiver_pk=frank_pk, amount=30)
    overflow_result = frank.receive_bundle_with_reasons(overflow_bundle)
    print_receive_results("Receive results:", overflow_result)

    reconciler = ReconciliationServer(issuer, policy=policy)
    print("\n10) Reconciliation results:")
    all_bundles = [bundle_ab, bundle_bc, bundle_cd, bundle_ab_second, bundle_bc_second, bundle_cb, bundle_be, overflow_bundle]
    for idx, bundle in enumerate(all_bundles, start=1):
        settlement = reconciler.process_bundle(bundle)
        print(f"Bundle {idx} ({bundle.bundle_id[:8]}):")
        for rec in settlement:
            print(vars(rec))

    print("\n11) Re-submit first bundle to demonstrate DOUBLE_SPEND:")
    second_settlement = reconciler.process_bundle(bundle_ab)
    for rec in second_settlement:
        print(vars(rec))

    print("\n12) Ledger snapshot:")
    for token_id, rec in reconciler.ledger.items():
        print(token_id[:8], rec.status, rec.reason)


if __name__ == "__main__":
    main()
