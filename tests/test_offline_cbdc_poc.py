import pytest

pytest.importorskip("cryptography")

from datetime import datetime, timedelta, timezone

from crypto.crypto_utils import generate_keypair, sign, verify
from issuer.issuer import Issuer
from issuer.reconciliation_server import ReconciliationServer
from protocol.policy import PolicyConfig
from wallet.offline_wallet import Wallet


def make_wallet(name: str, policy: PolicyConfig) -> Wallet:
    sk, pk = generate_keypair()
    return Wallet(owner_name=name, private_key_hex=sk, public_key_hex=pk, policy=policy)


def test_ed25519_sign_verify_roundtrip() -> None:
    sk, pk = generate_keypair()
    payload = b"offline-cbdc-message"

    sig = sign(payload, sk)

    assert verify(payload, sig, pk)
    assert not verify(b"tampered", sig, pk)


def test_wallet_create_payment_whole_token_and_receive() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=100, MAX_TOKEN_HOPS=5, MAX_WALLET_BALANCE=1_000, TOKEN_EXPIRY_SECONDS=3600)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)

    alice = make_wallet("Alice", policy)
    bob = make_wallet("Bob", policy)

    # Alice starts with one 30-unit token.
    alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=30))

    bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=25)
    results = bob.receive_bundle(bundle)

    assert all(ok for _, ok in results)
    assert alice.balance() == 0
    assert bob.balance() == 30


def test_receive_bundle_replay_is_rejected() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=100, MAX_TOKEN_HOPS=5, MAX_WALLET_BALANCE=1_000, TOKEN_EXPIRY_SECONDS=3600)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)

    alice = make_wallet("Alice", policy)
    bob = make_wallet("Bob", policy)

    alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=10))
    bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=10)

    first = bob.receive_bundle(bundle)
    second = bob.receive_bundle(bundle)

    assert first[0][1] is True
    assert second[0][1] is False


def test_expired_token_transfer_rejected() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=100, MAX_TOKEN_HOPS=5, MAX_WALLET_BALANCE=1_000, TOKEN_EXPIRY_SECONDS=1)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)

    alice = make_wallet("Alice", policy)
    bob = make_wallet("Bob", policy)

    token = issuer.mint_token(owner_pk=alice.public_key_hex, value=10)
    token.created_at = datetime.now(tz=timezone.utc) - timedelta(seconds=60)
    alice.receive_token(token)

    bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=10)
    result = bob.receive_bundle(bundle)

    assert result[0][1] is False


def test_reconciliation_detects_double_spend() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=100, MAX_TOKEN_HOPS=5, MAX_WALLET_BALANCE=1_000, TOKEN_EXPIRY_SECONDS=3600)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    reconciler = ReconciliationServer(issuer)

    alice = make_wallet("Alice", policy)
    bob = make_wallet("Bob", policy)

    alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=10))
    bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=10)

    first = reconciler.process_bundle(bundle)
    second = reconciler.process_bundle(bundle)

    assert first[0].status == "ACCEPTED"
    assert second[0].status == "DOUBLE_SPEND"


def test_t8_wallet_rejects_payment_above_max_balance() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=1_000, MAX_TOKEN_HOPS=7, MAX_WALLET_BALANCE=10_000, TOKEN_EXPIRY_SECONDS=604800)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)

    payer = make_wallet("Payer", policy)
    receiver = make_wallet("Receiver", policy)

    receiver.receive_token(issuer.mint_token(owner_pk=receiver.public_key_hex, value=9_500))
    payer.receive_token(issuer.mint_token(owner_pk=payer.public_key_hex, value=1_000))

    bundle = payer.create_payment(receiver_pk=receiver.public_key_hex, amount=1_000)
    results = receiver.receive_payment(bundle)

    assert results[0][1] is False
    assert results[0][2] == "MAX_BALANCE_EXCEEDED"


def test_t9_lost_device_recovery_reissues_safe_balance() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=1_000, MAX_TOKEN_HOPS=7, MAX_WALLET_BALANCE=10_000, TOKEN_EXPIRY_SECONDS=604800)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    simulated_now = datetime.now(tz=timezone.utc)
    server = ReconciliationServer(issuer, policy=policy, now_fn=lambda: simulated_now)

    alice_sk, alice_pk = generate_keypair()
    bob_sk, bob_pk = generate_keypair()
    charlie_sk, charlie_pk = generate_keypair()
    alice = Wallet("Alice", alice_sk, alice_pk, policy)
    bob = Wallet("Bob", bob_sk, bob_pk, policy)
    charlie = Wallet("Charlie", charlie_sk, charlie_pk, policy)

    for _ in range(5):
        alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=100))

    bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=100)
    receive_results = bob.receive_payment(bundle)
    assert receive_results[0][1] is True

    # Bob forwards one token, then Charlie settles it.
    bob_to_charlie = bob.create_payment(receiver_pk=charlie.public_key_hex, amount=100)
    received_by_charlie = charlie.receive_payment(bob_to_charlie)
    assert received_by_charlie[0][1] is True
    settlement = server.process_bundle(bob_to_charlie)
    assert settlement[0].status == "ACCEPTED"

    # Alice loses device and revokes old wallet.
    server.revoke_wallet(alice.public_key_hex)

    # Recovery before TTL should fail.
    with pytest.raises(ValueError, match="RECOVERY_WAIT_NOT_ELAPSED"):
        server.reissue_recovered_balance(alice.public_key_hex, new_public_key=generate_keypair()[1])

    # One week passes in simulation.
    simulated_now = simulated_now + timedelta(seconds=policy.TOKEN_EXPIRY_SECONDS + 1)
    _new_alice_sk, new_alice_pk = generate_keypair()
    recovered = server.reissue_recovered_balance(alice.public_key_hex, new_alice_pk)

    assert sum(token.value for token in recovered) == 400
