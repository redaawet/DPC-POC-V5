from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from crypto.crypto_utils import generate_keypair
from issuer.issuer import Issuer
from issuer.reconciliation_server import ReconciliationServer
from protocol.policy import PolicyConfig
from protocol.proxy_sync import SyncHeartbeat, _heartbeat_payload, create_heartbeat, relay_heartbeat
from wallet.offline_wallet import Wallet


def _wallet(name: str, policy: PolicyConfig) -> Wallet:
    sk, pk = generate_keypair()
    return Wallet(name, sk, pk, policy)


def test_valid_heartbeat_updates_last_sync() -> None:
    policy = PolicyConfig()
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    wallet = _wallet("A", policy)
    token = issuer.mint_token(wallet.public_key_hex, 100)
    wallet.receive_token(token)
    server = ReconciliationServer(issuer, policy=policy)

    hb = create_heartbeat(bytes.fromhex(wallet.private_key_hex), bytes.fromhex(wallet.public_key_hex), [token.token_id])
    result = relay_heartbeat(hb, server)

    assert result["status"] == "ok"
    assert result["refreshed_tokens"] == [token.token_id]
    assert token.token_id in server.last_sync


def test_forged_heartbeat_signature_is_rejected() -> None:
    policy = PolicyConfig()
    wallet = _wallet("A", policy)
    _wrong_sk, wrong_pk = generate_keypair()
    hb = create_heartbeat(bytes.fromhex(wallet.private_key_hex), bytes.fromhex(wallet.public_key_hex), ["tok"])
    hb.signature = bytes.fromhex(wrong_pk)[:32]
    server = ReconciliationServer(Issuer(*generate_keypair()), policy=policy)

    assert relay_heartbeat(hb, server)["status"] == "invalid_signature"


def test_expired_heartbeat_is_rejected() -> None:
    policy = PolicyConfig(TOKEN_EXPIRY_SECONDS=10)
    issuer_sk, issuer_pk = generate_keypair()
    server = ReconciliationServer(Issuer(issuer_sk, issuer_pk), policy=policy)
    wallet = _wallet("A", policy)
    old_timestamp = time_value = datetime.now(tz=timezone.utc).timestamp() - 11
    payload = _heartbeat_payload(bytes.fromhex(wallet.public_key_hex), ["tok"], time_value)
    from crypto.crypto_utils import sign

    hb = SyncHeartbeat(
        wallet_pk=bytes.fromhex(wallet.public_key_hex),
        token_ids=["tok"],
        timestamp=old_timestamp,
        signature=bytes.fromhex(sign(payload, wallet.private_key_hex)),
    )

    assert relay_heartbeat(hb, server)["status"] == "expired_heartbeat"


def test_tampered_token_ids_are_rejected() -> None:
    policy = PolicyConfig()
    wallet = _wallet("A", policy)
    hb = create_heartbeat(bytes.fromhex(wallet.private_key_hex), bytes.fromhex(wallet.public_key_hex), ["tok-a"])
    hb.token_ids.append("tok-b")
    server = ReconciliationServer(Issuer(*generate_keypair()), policy=policy)

    assert relay_heartbeat(hb, server)["status"] == "invalid_signature"


def test_full_t5_proxy_sync_keeps_token_non_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = PolicyConfig(TOKEN_EXPIRY_SECONDS=604800)
    t0 = datetime.now(tz=timezone.utc)
    issuer_sk, issuer_pk = generate_keypair()
    issuer = Issuer(issuer_sk, issuer_pk)
    offline = _wallet("Offline", policy)
    online = _wallet("Online", policy)
    token = issuer.mint_token(offline.public_key_hex, 100)
    offline.receive_token(token)

    day6 = t0 + timedelta(days=6)
    monkeypatch.setattr("protocol.proxy_sync.time.time", lambda: day6.timestamp())
    hb = create_heartbeat(bytes.fromhex(offline.private_key_hex), bytes.fromhex(offline.public_key_hex), [token.token_id])

    day65 = t0 + timedelta(days=6.5)
    server = ReconciliationServer(issuer, policy=policy, now_fn=lambda: day65)
    result = relay_heartbeat(hb, server)
    day69 = t0 + timedelta(days=6.9)

    assert online.public_key_hex
    assert result["status"] == "ok"
    assert server.is_token_expired(token.token_id, at_time=day69) is False
