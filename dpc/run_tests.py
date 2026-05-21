"""Self-contained functional test runner for the DPC PoC."""

from __future__ import annotations

import secrets
import sys
import time

from ble_session_simulator import BLESession
from constants import GENESIS_HASH, MAX_OFFLINE_HOPS
from crypto_utils import DPCKeyPair
from exceptions import ChainIntegrityError, FirstClaimConflictError, HopLimitExceededError, TokenExpiredError, TransactionValueCapError, WalletBalanceCapError
from reconciliation_engine import IssuerLedger
from token_model import TransferChain, TransferRecord
from wallet import DPCWallet


def _wallet(name: str) -> DPCWallet:
    return DPCWallet(name, DPCKeyPair.generate())


def _mint_to(ledger: IssuerLedger, issuer: DPCKeyPair, wallet: DPCWallet, amount: int) -> str:
    token, chain = ledger.mint_token(issuer, wallet.keypair.public_key_hex(), amount)
    wallet.receive_token(token, chain)
    return token.token_id


def test_T1() -> None:
    desc = "Maximum Offline Hops Enforcement"
    print(f"[RUNNING] T1: {desc}")
    ledger, issuer = IssuerLedger(), DPCKeyPair.generate()
    wallets = [_wallet(f"W{i}") for i in range(9)]
    token_id = _mint_to(ledger, issuer, wallets[0], 50_000)
    token = None
    chain = []
    for i in range(7):
        token, chain = wallets[i].send_token(token_id, wallets[i + 1].keypair.public_key_hex())
        wallets[i + 1].receive_token(token, chain)
    assert chain[-1].hop_index == 7
    try:
        wallets[7].send_token(token_id, wallets[8].keypair.public_key_hex())
        raise AssertionError("8th non-return hop was not blocked")
    except HopLimitExceededError as exc:
        assert "hop limit" in str(exc).lower()
    assert token_id in wallets[7].utr.list_tokens()
    token, chain = wallets[7].send_token(token_id, wallets[0].keypair.public_key_hex())
    assert chain[-1].hop_index == 1
    print(f"Hop blocked at {MAX_OFFLINE_HOPS + 1}; return reset hop={chain[-1].hop_index}")
    print(f"[PASS]    T1: {desc}")


def test_T2() -> None:
    desc = "Maximum Wallet Balance Cap"
    print(f"[RUNNING] T2: {desc}")
    ledger, issuer, wallet_a = IssuerLedger(), DPCKeyPair.generate(), _wallet("A")
    for _ in range(10):
        _mint_to(ledger, issuer, wallet_a, 100_000)
    token, chain = ledger.mint_token(issuer, wallet_a.keypair.public_key_hex(), 1)
    before = wallet_a.get_balance()
    try:
        wallet_a.receive_token(token, chain)
        raise AssertionError("Wallet balance cap was not enforced")
    except WalletBalanceCapError:
        assert wallet_a.get_balance() == 1_000_000
        assert token.token_id not in wallet_a.utr.list_tokens()
    print(f"Pre-rejection balance={before}")
    print(f"[PASS]    T2: {desc}")


def test_T3() -> None:
    desc = "Single-Transaction Value Cap"
    print(f"[RUNNING] T3: {desc}")
    ledger, issuer, wallet_a, wallet_b = IssuerLedger(), DPCKeyPair.generate(), _wallet("A"), _wallet("B")
    try:
        ledger.mint_token(issuer, wallet_a.keypair.public_key_hex(), 110_000)
        raise AssertionError("Mint over cap was not rejected")
    except TransactionValueCapError:
        assert True
    token_id = _mint_to(ledger, issuer, wallet_a, 100_000)
    token, chain = wallet_a.send_token(token_id, wallet_b.keypair.public_key_hex())
    wallet_b.receive_token(token, chain)
    token_id = _mint_to(ledger, issuer, wallet_a, 100_000)
    receipt = wallet_a.utr.get_receipt(token_id)
    receipt.final_hop.amount_subunits = 100_100
    receipt.full_chain[-1].amount_subunits = 100_100
    try:
        wallet_a.send_token(token_id, wallet_b.keypair.public_key_hex())
        raise AssertionError("Tampered over-cap transfer was not rejected")
    except TransactionValueCapError:
        assert token_id in wallet_a.utr.list_tokens()
    try:
        TransferChain(receipt.full_chain).validate_integrity(receipt.token)
        raise AssertionError("Tampered chain was not rejected")
    except ChainIntegrityError:
        assert True
    print("Cap and tamper checks raised expected errors")
    print(f"[PASS]    T3: {desc}")


def test_T4() -> None:
    desc = "Token TTL Expiry"
    print(f"[RUNNING] T4: {desc}")
    ledger, issuer, wallet_a, wallet_b = IssuerLedger(), DPCKeyPair.generate(), _wallet("A"), _wallet("B")
    token_id = _mint_to(ledger, issuer, wallet_a, 10_000)
    expired_token = wallet_a.utr.get_receipt(token_id).token
    expired_token.ttl_expiry = int(time.time()) - 1
    expired_token.issuer_signature = issuer.sign(expired_token.genesis_payload_bytes()).hex()
    try:
        wallet_a.send_token(token_id, wallet_b.keypair.public_key_hex())
        raise AssertionError("Expired token was not rejected")
    except TokenExpiredError:
        assert token_id in wallet_a.utr.list_tokens()
    token_id2 = _mint_to(ledger, issuer, wallet_a, 10_000)
    token2 = wallet_a.utr.get_receipt(token_id2).token
    try:
        token2.is_expired(reference_time=token2.issued_at - 1)
        raise AssertionError("Clock rollback was not detected")
    except TokenExpiredError as exc:
        assert "Clock rollback detected" in str(exc)
    token_id3 = _mint_to(ledger, issuer, wallet_a, 10_000)
    token3 = wallet_a.utr.get_receipt(token_id3).token
    token3.ttl_expiry = int(time.time()) + 10
    token3.issuer_signature = issuer.sign(token3.genesis_payload_bytes()).hex()
    sent_token, sent_chain = wallet_a.send_token(token_id3, wallet_b.keypair.public_key_hex())
    wallet_b.receive_token(sent_token, sent_chain)
    print(f"Remaining TTL seconds={token3.ttl_expiry - int(time.time())}")
    print(f"[PASS]    T4: {desc}")


def test_T5() -> None:
    desc = "Delegated Reconciliation (Proxy Sync)"
    print(f"[RUNNING] T5: {desc}")
    ledger, issuer = IssuerLedger(), DPCKeyPair.generate()
    a, b, c, proxy = _wallet("A"), _wallet("B"), _wallet("C"), _wallet("P")
    tid_a = _mint_to(ledger, issuer, a, 10_000)
    tid_b = _mint_to(ledger, issuer, b, 20_000)
    tid_c = _mint_to(ledger, issuer, c, 30_000)
    token_a, chain_a = a.send_token(tid_a, b.keypair.public_key_hex())
    b.receive_token(token_a, chain_a)
    token_a, chain_a = b.send_token(tid_a, c.keypair.public_key_hex())
    c.receive_token(token_a, chain_a)
    token_c, chain_c = c.send_token(tid_c, a.keypair.public_key_hex())
    a.receive_token(token_c, chain_c)
    receipt_b = b.utr.get_receipt(tid_b)
    results = ledger.proxy_sync(
        proxy.keypair.public_key_hex(),
        [
            (c.keypair.public_key_hex(), token_a, chain_a),
            (b.keypair.public_key_hex(), receipt_b.token, receipt_b.full_chain),
            (a.keypair.public_key_hex(), token_c, chain_c),
        ],
    )
    assert ledger.get_settled_count() == 3
    for result in results:
        print(f"Settled claimer={result['claimer_pubkey'][:12]} depth={result['chain_depth']}")
    print(f"[PASS]    T5: {desc}")


def test_T6() -> None:
    desc = "Token Lifecycle Reset on Return"
    print(f"[RUNNING] T6: {desc}")
    ledger, issuer = IssuerLedger(), DPCKeyPair.generate()
    wallets = [_wallet(name) for name in ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]]
    token_id = _mint_to(ledger, issuer, wallets[0], 10_000)
    token, chain = wallets[0].send_token(token_id, wallets[1].keypair.public_key_hex())
    wallets[1].receive_token(token, chain)
    token, chain = wallets[1].send_token(token_id, wallets[2].keypair.public_key_hex())
    wallets[2].receive_token(token, chain)
    token, chain = wallets[2].send_token(token_id, wallets[0].keypair.public_key_hex())
    wallets[0].receive_token(token, chain)
    assert chain[-1].hop_index == 1
    holder = 0
    for target in [3, 4, 5, 6, 7, 8]:
        token, chain = wallets[holder].send_token(token_id, wallets[target].keypair.public_key_hex())
        wallets[target].receive_token(token, chain)
        print(f"Transfer to {wallets[target].wallet_id}: hop={chain[-1].hop_index}")
        holder = target
    try:
        wallets[holder].send_token(token_id, wallets[9].keypair.public_key_hex())
        raise AssertionError("Post-reset hop overflow was not blocked")
    except HopLimitExceededError:
        assert token_id in wallets[holder].utr.list_tokens()
    print(f"[PASS]    T6: {desc}")


def test_T7() -> None:
    desc = "P2P Change Generation (Swap)"
    print(f"[RUNNING] T7: {desc}")
    ledger, issuer, wallet_a, wallet_b = IssuerLedger(), DPCKeyPair.generate(), _wallet("A"), _wallet("B")
    token_id = _mint_to(ledger, issuer, wallet_a, 100_000)
    payment_token, payment_chain, change_token, change_chain = wallet_a.swap_change(
        token_id, 35_000, wallet_b.keypair.public_key_hex(), wallet_a.keypair.public_key_hex()
    )
    wallet_b.receive_token(payment_token, payment_chain)
    wallet_a.receive_token(change_token, change_chain)
    assert wallet_b.get_balance() == 35_000
    assert wallet_a.get_balance() == 65_000
    TransferChain(payment_chain).validate_integrity(payment_token)
    TransferChain(change_chain).validate_integrity(change_token)
    print(f"Split balances: A={wallet_a.get_balance()} B={wallet_b.get_balance()}")
    print(f"[PASS]    T7: {desc}")


def test_T8() -> None:
    desc = "Double-Spending Prevention"
    print(f"[RUNNING] T8: {desc}")
    ledger, issuer, wallet_a, wallet_b, wallet_c = IssuerLedger(), DPCKeyPair.generate(), _wallet("A"), _wallet("B"), _wallet("C")
    token_id = _mint_to(ledger, issuer, wallet_a, 10_000)
    original = wallet_a.utr.get_receipt(token_id)
    token_b, chain_b = wallet_a.send_token(token_id, wallet_b.keypair.public_key_hex())
    wallet_b.receive_token(token_b, chain_b)
    forged = TransferRecord(
        token_id=original.token.token_id,
        hop_index=1,
        sender_pubkey_hex=wallet_a.keypair.public_key_hex(),
        receiver_pubkey_hex=wallet_c.keypair.public_key_hex(),
        amount_subunits=original.token.amount_subunits,
        nonce=secrets.token_hex(16),
        prev_hash=original.full_chain[-1].chain_hash,
    )
    forged.sign(wallet_a.keypair.private_key_bytes())
    chain_c = original.full_chain + [forged]
    result = ledger.settle_token(wallet_b.keypair.public_key_hex(), token_b, chain_b)
    assert result["chain_depth"] == len(chain_b)
    try:
        ledger.settle_token(wallet_c.keypair.public_key_hex(), original.token, chain_c)
        raise AssertionError("Double-spend conflict was not detected")
    except FirstClaimConflictError:
        assert ledger.is_blacklisted(wallet_c.keypair.public_key_hex())
        assert not ledger.is_blacklisted(wallet_b.keypair.public_key_hex())
    tampered = [TransferRecord.from_dict(record.to_dict()) for record in chain_b]
    tampered[0].amount_subunits = 1
    try:
        ledger.settle_token(wallet_b.keypair.public_key_hex(), token_b, tampered)
        raise AssertionError("Tampered settled chain was not rejected")
    except ChainIntegrityError:
        assert True
    session = BLESession(wallet_a.keypair, wallet_b.keypair)
    received_token, received_chain = session.simulate_transfer(token_b, chain_b)
    assert received_token.token_id == token_b.token_id
    assert len(received_chain) == len(chain_b)
    print(f"Conflict depths: B={len(chain_b)} C={len(chain_c)}")
    print(f"[PASS]    T8: {desc}")


if __name__ == "__main__":
    import traceback

    tests = [
        ("T1", "Maximum Offline Hops Enforcement", test_T1),
        ("T2", "Maximum Wallet Balance Cap", test_T2),
        ("T3", "Single-Transaction Value Cap", test_T3),
        ("T4", "Token TTL Expiry", test_T4),
        ("T5", "Delegated Reconciliation (Proxy Sync)", test_T5),
        ("T6", "Token Lifecycle Reset on Return", test_T6),
        ("T7", "P2P Change Generation (Swap)", test_T7),
        ("T8", "Double-Spending Prevention", test_T8),
    ]
    passed, failed = 0, 0
    separator = "-" * 60
    print("\n" + "=" * 60)
    print("  DPC PoC - Functional Test Suite (T1-T8)")
    print("=" * 60)
    for code, name, fn in tests:
        print(f"\n{separator}")
        try:
            fn()
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"[FAIL]    {code}: {name}")
            print(f"          Exception: {type(exc).__name__}: {exc}")
            traceback.print_exc()
    print(f"\n{'=' * 60}")
    print(f"  Results: {passed} PASSED / {failed} FAILED out of {len(tests)} tests")
    print("=" * 60 + "\n")
    sys.exit(0 if failed == 0 else 1)
