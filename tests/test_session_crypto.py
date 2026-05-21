import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from crypto.crypto_utils import generate_keypair
from crypto.session import (
    decrypt_bundle,
    derive_session_key,
    ecdh_shared_secret,
    ed25519_sk_to_x25519_sk,
    encrypt_bundle,
)
from issuer.issuer import Issuer
from protocol.network_simulator import send_bundle
from protocol.policy import PolicyConfig
from wallet.offline_wallet import Wallet


def _wallet(name: str, policy: PolicyConfig) -> Wallet:
    sk, pk = generate_keypair()
    return Wallet(name, sk, pk, policy)


def test_session_encrypt_decrypt_roundtrip() -> None:
    session_key = b"1" * 32
    plaintext = b"dpc payment bundle"

    nonce, ciphertext = encrypt_bundle(plaintext, session_key)

    assert decrypt_bundle(nonce, ciphertext, session_key) == plaintext


def test_session_wrong_key_rejects_ciphertext() -> None:
    nonce, ciphertext = encrypt_bundle(b"dpc", b"1" * 32)

    with pytest.raises(Exception):
        decrypt_bundle(nonce, ciphertext, b"2" * 32)


def test_ed25519_to_x25519_derivation_is_deterministic() -> None:
    sk, _pk = generate_keypair()

    first = ed25519_sk_to_x25519_sk(bytes.fromhex(sk)).private_bytes_raw()
    second = ed25519_sk_to_x25519_sk(bytes.fromhex(sk)).private_bytes_raw()

    assert first == second


def test_two_parties_derive_same_shared_secret() -> None:
    alice_sk, _alice_pk = generate_keypair()
    bob_sk, _bob_pk = generate_keypair()
    alice_x = ed25519_sk_to_x25519_sk(bytes.fromhex(alice_sk))
    bob_x = ed25519_sk_to_x25519_sk(bytes.fromhex(bob_sk))
    alice_pub = alice_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    bob_pub = bob_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    assert ecdh_shared_secret(alice_x, bob_pub) == ecdh_shared_secret(bob_x, alice_pub)


def test_network_simulator_encrypted_bundle_integration() -> None:
    policy = PolicyConfig(MAX_TX_VALUE=1_000, MAX_HOPS=7, MAX_BALANCE=10_000, TOKEN_EXPIRY_SECONDS=604800)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    alice = _wallet("Alice", policy)
    bob = _wallet("Bob", policy)
    alice.receive_token(issuer.mint_token(owner_pk=alice.public_key_hex, value=100))
    bundle = alice.create_payment(receiver_pk=bob.public_key_hex, amount=100)

    results = send_bundle(alice, bob, bundle, encrypt=True)

    assert results[0][1] is True
    assert bob.balance() == 100
