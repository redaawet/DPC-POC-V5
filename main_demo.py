"""Demonstration scenario for offline CBDC token payments."""
from __future__ import annotations

import time

from crypto.crypto_utils import generate_keypair
from issuer.issuer import Issuer
from issuer.reconciliation_server import ReconciliationServer
from protocol.network_simulator import send_bundle
from protocol.policy import PolicyConfig, PolicyError
from wallet.offline_wallet import Wallet

# Policy values match the thesis specification (Chapter 3 / Chapter 5):
#   MAX_TX_VALUE     = 1 000 ETB   (per-transaction cap, T3)
#   MAX_HOPS         = 7           (offline hop limit, T1)
#   MAX_BALANCE      = 10 000 ETB  (wallet accumulation cap, T2)
#   TOKEN_EXPIRY     = 604 800 s   (7-day TTL, T4)
# See tests/test_offline_cbdc_poc.py for the full automated test suite.


def make_wallet(name: str, policy: PolicyConfig) -> Wallet:
    """Create a wallet with a fresh Ed25519 key pair."""
    sk, pk = generate_keypair()
    return Wallet(name, sk, pk, policy)


def print_wallet_state(label: str, wallet: Wallet) -> None:
    """Print compact wallet state for the demo."""
    print(f"{label} balance: {wallet.balance()} ETB")
    print(f"{label} UTR: {[(t.token_id[:8], t.value, t.nonce, t.hop_count) for t in wallet.snapshot_tokens()]}")


def print_receive_results(step: str, results: list[tuple[str, bool, str]]) -> None:
    """Print receiver-side accept/reject results."""
    print(step)
    for transfer_id, ok, reason in results:
        status = "ACCEPTED" if ok else "REJECTED"
        print(f"  transfer={transfer_id[:8]} status={status} reason={reason}")


def main() -> None:
    policy = PolicyConfig(
        MAX_TX_VALUE=1000,
        MAX_HOPS=7,
        MAX_BALANCE=10000,
        TOKEN_EXPIRY_SECONDS=604800,  # 7 days
    )
    print(
        "Policy: "
        f"MAX_TX_VALUE={policy.MAX_TX_VALUE}, MAX_HOPS={policy.MAX_HOPS}, "
        f"MAX_BALANCE={policy.MAX_BALANCE}, TOKEN_EXPIRY_SECONDS={policy.TOKEN_EXPIRY_SECONDS}"
    )

    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    alice = make_wallet("Alice", policy)
    bob = make_wallet("Bob", policy)
    carol = make_wallet("Carol", policy)
    dave = make_wallet("Dave", policy)
    erin = make_wallet("Erin", policy)
    print("1) Issuer and wallets created")

    alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=500))
    payment = alice.create_payment(receiver_pk=bob.public_key_hex, amount=500)
    encrypted_results = send_bundle(alice, bob, payment, encrypt=True)
    print(f"2) Alice -> Bob encrypted simulated BLE transfer: {encrypted_results}")
    print_wallet_state("Bob", bob)

    print("\n3) T2 balance cap rejection at 10,000 ETB:")
    carol.receive_token(issuer.mint_token(owner_pk=carol.public_key_hex, value=9_500))
    dave.receive_token(issuer.mint_token(owner_pk=dave.public_key_hex, value=600))
    overflow_bundle = dave.create_payment(receiver_pk=carol.public_key_hex, amount=600)
    print_receive_results("Receive results:", carol.receive_bundle_with_reasons(overflow_bundle))

    print("\n4) T3 single transaction cap rejection at 1,200 ETB:")
    alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=1_200))
    try:
        alice.create_payment(receiver_pk=bob.public_key_hex, amount=1_200)
    except PolicyError as exc:
        print(f"  rejected: {exc}")

    print("\n5) T1 hop limit rejection on hop 8:")
    hop_token = issuer.mint_token(owner_pk=alice.public_key_hex, value=100)
    # Demo shortcut: start this token at hop 6 so one valid transfer reaches hop 7
    # and a tampered next-hop bundle demonstrates the hop-8 rejection without a long walkthrough.
    hop_token.nonce = 6
    hop_token.hop_count = 6
    alice.receive_token(hop_token)
    hop7_bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=100)
    assert bob.receive_bundle_with_reasons(hop7_bundle)[0][1] is True
    for token in bob.utr.values():
        token.nonce = 6
        token.hop_count = 6
    hop8_bundle = bob.create_payment(receiver_pk=dave.public_key_hex, amount=100)
    for transfer in hop8_bundle.transfers:
        transfer.nonce = 8
        transfer.hop_count = 8
    print_receive_results("Receive results:", dave.receive_bundle_with_reasons(hop8_bundle))

    print("\n6) T4 TTL expiry rejection:")
    expired_token = issuer.mint_token(owner_pk=erin.public_key_hex, value=100)
    erin.receive_token(expired_token)
    expired_bundle = erin.create_payment(receiver_pk=bob.public_key_hex, amount=100)
    for token in expired_bundle.tokens.values():
        token.issue_timestamp = int(time.time()) - 8 * 86400
    print_receive_results("Receive results:", bob.receive_bundle_with_reasons(expired_bundle))

    print("\n7) Reconciliation snapshot:")
    reconciler = ReconciliationServer(issuer, policy=policy)
    for idx, bundle in enumerate([payment, overflow_bundle, hop7_bundle], start=1):
        settlement = reconciler.process_bundle(bundle)
        print(f"Bundle {idx} ({bundle.bundle_id[:8]}): {[vars(rec) for rec in settlement]}")


if __name__ == "__main__":
    main()
