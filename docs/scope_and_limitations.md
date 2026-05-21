# DPC-POC-V5 - scope and implementation status

This document maps every feature claim in the thesis to its status in this proof-of-concept implementation.

## Implementation status

| Feature | Thesis section | Status | Location |
|---------|---------------|--------|----------|
| Ed25519 signing and verification | Section 3.4 | Implemented | `crypto/crypto_utils.py` |
| Hash-linked transfer chain (SHA-256) | Section 3.4 | Implemented | `digital_token/poc_models.py` |
| X25519 ECDH session key derivation | Section 3.4 | Implemented | `crypto/session.py` |
| ChaCha20-Poly1305 bundle encryption | Section 3.4 | Implemented | `crypto/session.py` |
| UTR / STR wallet registers | Section 3.2.3 | Implemented | `wallet/offline_wallet.py` |
| Hop-count limit enforcement (T1) | Section 5.1.1 | Implemented | `protocol/policy.py` |
| Wallet balance cap (T2) | Section 5.1.2 | Implemented | `protocol/policy.py` |
| Per-transaction value cap (T3) | Section 5.1.3 | Implemented | `protocol/policy.py` |
| Token TTL expiry (T4) | Section 5.2.1 | Implemented | `wallet/offline_wallet.py` |
| Proxy synchronisation / relay (T5) | Section 5.2.2 | Implemented | `protocol/proxy_sync.py` |
| Token lifecycle reset on return (T6) | Section 5.3.1 | Implemented | `wallet/offline_wallet.py` |
| Peer-to-peer change / swap (T7) | Section 5.3.2 | Implemented | `wallet/offline_wallet.py` |
| Double-spend detection (T8) | Section 5.3.3 | Implemented | `issuer/reconciliation_server.py` |
| Lost-device recovery (T9 - bonus) | Section 6.2.1 | Implemented | `issuer/reconciliation_server.py` |
| Multi-token payment bundles | Section 3.2.3 | Implemented | `digital_token/poc_models.py` |
| Replay protection | Section 3.4 | Implemented | `wallet/offline_wallet.py` |
| Trusted Execution Environment (TEE) | Section 3.4.2 | Specified, not implemented | Production Android/iOS only |
| Threshold KYC / AML controls | Section 3.4 | Specified, not implemented | Requires regulatory integration |
| Physical BLE transport (GATT) | Section 3.3 | Specified, not implemented | `protocol/network_simulator.py` simulates transport |
| Mobile application UI | Section 6.2.1 | Next phase | `mobile/` placeholder |
| Biometric key binding | Section 3.4 | Specified, not implemented | TEE-dependent |

## What "specified, not implemented" means

Features in these rows are fully specified in the thesis architecture and security model but are intentionally deferred to the next research phase. The PoC demonstrates protocol correctness in simulation; these features require physical hardware, regulatory integration, or an end-user interface to validate meaningfully.

The simulation layer (`protocol/network_simulator.py`) is a deliberate stand-in for BLE. It passes bundles between wallet objects using the same data structures and policy checks that a real BLE GATT implementation would use, so protocol correctness is validated independently of the transport.

## Running the tests

```bash
python -m venv .venv
pip install cryptography pytest
pytest -q
pytest -q tests/test_offline_cbdc_poc.py
pytest -q tests/test_session_crypto.py
pytest -q tests/test_proxy_sync.py
pytest -q tests/test_offline_cbdc_poc.py -k "t9 or recovery"
```

## Policy values (thesis-aligned)

| Parameter | Value | Thesis reference |
|-----------|-------|-----------------|
| MAX_TX_VALUE | 1 000 ETB | Section 3.4, T3 |
| MAX_HOPS | 7 | Section 3.4, T1 |
| MAX_BALANCE | 10 000 ETB | Section 3.4, T2 |
| TOKEN_EXPIRY_SECONDS | 604 800 (7 days) | Section 3.4, T4 |
