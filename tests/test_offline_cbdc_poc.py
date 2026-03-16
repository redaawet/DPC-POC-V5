from datetime import datetime, timedelta, timezone

from offline_cbdc_poc.crypto_utils import generate_keypair, sign, verify
from offline_cbdc_poc.issuer import Issuer
from offline_cbdc_poc.policy import PolicyConfig
from offline_cbdc_poc.reconciliation_server import ReconciliationServer
from offline_cbdc_poc.wallet import Wallet


def make_wallet(name: str, policy: PolicyConfig) -> Wallet:
    sk, pk = generate_keypair()
    return Wallet(owner_name=name, private_key_hex=sk, public_key_hex=pk, policy=policy)


def test_ed25519_sign_verify_roundtrip() -> None:
    sk, pk = generate_keypair()
    payload = b"offline-cbdc-message"

    sig = sign(payload, sk)

    assert verify(payload, sig, pk)
    assert not verify(b"tampered", sig, pk)


def test_wallet_create_payment_split_and_receive() -> None:
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
    assert alice.balance() == 5
    assert bob.balance() == 25


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
