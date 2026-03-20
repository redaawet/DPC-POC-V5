# Offline CBDC PoC

A Python 3.10+ proof-of-concept for offline CBDC bearer-token payments between wallets.

## Requirements

- Python 3.10+
- Recommended: `cryptography` package (`pip install cryptography`) for cross-platform Ed25519 support.
- Optional fallback: OpenSSL CLI available on `PATH`.

## Modules

- `crypto/crypto_utils.py` - Ed25519 key generation/sign/verify.
- `digital_token/poc_models.py` - Token, Transfer, PaymentBundle models.
- `dpc_models.py` - compatibility exports for `Policy`, `Token`, `Transfer`, `PaymentBundle`.
- `wallet/offline_wallet.py` - UTR/STR wallet logic, payment creation, replay protection.
- `issuer/issuer.py` - Central bank simulator minting signed root tokens.
- `protocol/policy.py` - configurable policy caps.
- `protocol/network_simulator.py` - offline BLE/NFC style bundle send.
- `issuer/reconciliation_server.py` - settlement, chain checks, double-spend detection.
- `main_demo.py` - complete scenario walkthrough.

## Run

```bash
python main_demo.py
```

## How to test the system (step-by-step)

### 1) Environment setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install cryptography pytest
```

### 2) Run all automated tests

```bash
pytest -q
```

If `cryptography` is missing, some test modules are intentionally skipped.

### 3) Run only the Offline CBDC PoC tests

```bash
pytest -q tests/test_offline_cbdc_poc.py
```

### 4) Run the interactive/demo flow

```bash
python main_demo.py
```

This shows issuance, offline payment hops, policy-based rejections, and settlement results.

## How to use the PoC for lost-device recovery (T9 flow)

This is the practical sequence to validate the “report lost → wait settlement window → recover safe balance” workflow:

1. **Mint funds to Alice** (e.g., `5 x 100` ETB tokens).
2. **Alice pays Bob offline** (e.g., `100` ETB).
3. **Bob syncs** the received token bundle to the reconciliation server.
4. **Alice reports device loss** by calling `revoke_wallet(alice_public_key)`.
5. Wait until: `current_time > revocation_time + TOKEN_TTL_SECONDS` (1 week).
6. Reconstruct recoverable value:
   - `issued_total - claimed_total = safe_balance`
   - via `reconstruct_recovery(alice_public_key)`.
7. Reissue recovered value to Alice’s new key using:
   - `reissue_recovered_balance(old_alice_pk, new_alice_pk, at_time=...)`.

### Commands to run recovery-focused tests

```bash
pytest -q tests/test_offline_cbdc_poc.py -k "t9 or recovery or revoked"
```

## Features implemented

- Offline peer-to-peer transfer bundles.
- Ed25519 signatures for issuer and transfer messages.
- UTR (unspent) and STR (spent) registers.
- Multi-token payment bundles.
- Policy cap enforcement for `MAX_TX_VALUE`, `MAX_TOKEN_HOPS`, `MAX_WALLET_BALANCE`, `TOKEN_EXPIRY_SECONDS`.
- Cash-like change handling where receivers return change using their own tokens.
- Replay protection using processed transfer IDs.
- Reconciliation with double-spend handling (`first accepted`, `second DOUBLE_SPEND`).
