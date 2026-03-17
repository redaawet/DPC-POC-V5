# Offline CBDC PoC

A Python 3.10+ proof-of-concept for offline CBDC bearer-token payments between wallets.

## Requirements

- Python 3.10+
- Recommended: `cryptography` package (`pip install cryptography`) for cross-platform Ed25519 support.
- Optional fallback: OpenSSL CLI available on `PATH`.

## Modules

- `crypto/crypto_utils.py` - Ed25519 key generation/sign/verify.
- `token/poc_models.py` - Token, Transfer, PaymentBundle models.
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

## Features implemented

- Offline peer-to-peer transfer bundles.
- Ed25519 signatures for issuer and transfer messages.
- UTR (unspent) and STR (spent) registers.
- Multi-token payment bundles.
- Policy cap enforcement for `MAX_TX_VALUE`, `MAX_TOKEN_HOPS`, `MAX_WALLET_BALANCE`, `TOKEN_EXPIRY_SECONDS`.
- Cash-like change handling where receivers return change using their own tokens.
- Replay protection using processed transfer IDs.
- Reconciliation with double-spend handling (`first accepted`, `second DOUBLE_SPEND`).
