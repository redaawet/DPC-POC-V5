# Digital Pocket Cash (DPC) – System Revision Report

## Overview

This revision report audits the repository after refactor and merged pull requests to document what is currently implemented, what architecture exists in practice, how the payment model behaves, and what work remains.

The implementation is functional as a proof-of-concept and is split across wallet/protocol/token/issuer/crypto layers, with both a canonical transfer-chain token path and an older/parallel offline bundle path.

---

## 1) Repository Structure Audit

### Expected architecture (target)

```text
dpc/
crypto/
token/
wallet/
protocol/
issuer/
```

### Observed architecture (current repository)

```text
crypto/
token/
wallet/
protocol/
issuer/
mobile/
tests/
scripts/
docs/
```

### Notes

- The `dpc/` package namespace is **not present** as a physical directory in the current tree.
- Core domains are implemented as top-level Python packages (`crypto`, `token`, `wallet`, `protocol`, `issuer`).
- `mobile/` currently contains a BLE test stub rather than production BLE integration.

### Module inventory and purpose

- **crypto/**
  - `crypto_utils.py`: Ed25519 helpers with `cryptography` primary backend and OpenSSL CLI fallback.
  - `signatures.py`: Ed25519 key/sign/verify helpers using base64 key material.
- **token/**
  - `token_model.py`: canonical token model with immutable identity/value, issuance payload, transfer chain validation.
  - `transfer_chain.py`: transfer record model with deterministic serialization and signatures.
  - `poc_models.py`: alternate PoC token/transfer/payment-bundle domain models.
- **wallet/**
  - `wallet.py`: canonical UTR/STR wallet with token selection, sending/receiving, sync.
  - `offline_wallet.py`: alternate offline wallet with policy checks and replay-protection for bundles.
- **protocol/**
  - `payment_session.py`: atomic cash-like payment session (payment + change + rollback).
  - `cash_payment.py`: wrapper for session execution.
  - `transfer_protocol.py`: two-phase discovery + transfer channel simulation.
  - `network_simulator.py`: local bundle send helper for offline wallet path.
  - `policy.py`: policy limits and expiry helper.
- **issuer/**
  - `issuer.py`: issuer minting/signing for PoC tokens.
  - `reconciliation.py`: reconciliation engine on canonical transfer-chain tokens.
  - `reconciliation_server.py`: bundle-settlement reconciler with double-spend ledger.
- **mobile/**
  - `ble_adapter_stub.py`: in-memory BLE adapter stub used by tests.
- **scripts/**
  - `run_demo.py`: end-to-end cash-like demo for canonical wallet/session flow.
- **tests/**
  - Unit/integration tests for crypto, token chain, wallet flows, cash payment, transfer protocol, reconciliation, and BLE stub behaviors.
- **docs/**
  - `system_implementation.md`: consolidated implementation summary.

---

## 2) Implemented Features by Component

## Crypto Module

**Location:** `crypto/`

**Implemented functionality:**
- Ed25519 key generation.
- Message signing.
- Signature verification.
- Dual backend strategy:
  - `crypto_utils.py`: `cryptography` preferred, OpenSSL fallback.
  - `signatures.py`: `cryptography`-based base64 helpers.

**Key files:**
- `crypto/crypto_utils.py`
- `crypto/signatures.py`

## Token Module

**Location:** `token/`

**Implemented functionality:**
- Canonical token model (`token_model.Token`) with immutable `token_id` and `value` after init.
- Issuance payload construction for deterministic signing.
- Transfer chain append and chain validation with signature continuity checks.
- Deterministic transfer serialization and signed transfer records.
- Alternate PoC models for payment bundles (`poc_models.py`).

**Key files:**
- `token/token_model.py`
- `token/transfer_chain.py`
- `token/poc_models.py`

## Wallet Module

**Location:** `wallet/`

**Implemented functionality:**
- Canonical wallet (`wallet.py`):
  - UTR/STR storage.
  - Greedy token selection (`sum >= amount`).
  - Sending tokens (append transfer, move UTR → STR).
  - Receiving/validating token payloads.
  - Atomic receive rollback on failure.
  - Sync/cleanup of spent register.
- Cash payment primitives:
  - `initiate_payment` and `process_payment` (receiver computes change).
- Alternate offline wallet (`offline_wallet.py`):
  - Bundle creation.
  - Replay protection (`processed_transfer_ids`).
  - Policy checks (max tx, hops, wallet balance, expiry).

**Key files:**
- `wallet/wallet.py`
- `wallet/offline_wallet.py`

## Protocol Module

**Location:** `protocol/`

**Implemented functionality:**
- Atomic payment session orchestration (`PaymentSession.execute`):
  - sender pays,
  - receiver validates and computes change,
  - receiver returns change,
  - rollback on failure.
- High-level cash payment wrapper (`execute_cash_payment`).
- Two-phase transfer protocol simulation:
  - discovery/open session,
  - transfer payload exchange.
- Simulated local communication for bundle path (`network_simulator.send_bundle`).
- Policy object and expiry utility.

**Key files:**
- `protocol/payment_session.py`
- `protocol/cash_payment.py`
- `protocol/transfer_protocol.py`
- `protocol/network_simulator.py`
- `protocol/policy.py`

## Issuer Module

**Location:** `issuer/`

**Implemented functionality:**
- Token minting and issuer signature (`issuer.py`).
- Settlement-time validation and double-spend detection:
  - Canonical chain path (`reconciliation.py`) accepts first valid submission and rejects duplicates.
  - Bundle path (`reconciliation_server.py`) validates transfer signature, issuer root, and rejects repeated token settlement as `DOUBLE_SPEND`.

**Key files:**
- `issuer/issuer.py`
- `issuer/reconciliation.py`
- `issuer/reconciliation_server.py`

---

## 3) Cash-Like Payment Model Verification

### Findings

The implemented canonical flow **does follow** the cash-like model:

- Tokens are treated as bearer objects transferred whole between wallets.
- Sender chooses existing tokens whose sum covers the price (`select_tokens`), rather than minting split fragments.
- Receiver computes change (`total - price`) and returns its own tokens back to sender.
- Session orchestration executes payment + change exchange atomically with rollback support.

### Example behavior in system

- Sender → Receiver: payment tokens covering amount.
- Receiver → Sender: change tokens from receiver wallet.

### Token-splitting check

No explicit token value-splitting function is implemented in the canonical `token_model` + `wallet` + `payment_session` path.

**Conclusion:** No direct token splitting detected in the canonical flow.

---

## 4) Test Coverage Review

### Present test modules

- `tests/test_crypto.py`
- `tests/test_token.py`
- `tests/test_wallet_flow.py` *(note: expected name `test_wallet.py` not present)*
- `tests/test_cash_payment.py`
- `tests/test_reconciliation.py`
- `tests/test_transfer_protocol.py`
- `tests/test_offline_cbdc_poc.py`
- `tests/mobile/test_ble_flow.py`

### What each verifies

- **test_crypto.py**
  - Ed25519 sign/verify success path.
  - Verification failure with wrong public key.

- **test_token.py**
  - Token issuance signature + transfer-chain validation.
  - Rejection when transfer chain is tampered.

- **test_wallet_flow.py**
  - UTR/STR lifecycle (add/send/receive/sync).
  - Atomic receive rollback when payload validation fails.

- **test_cash_payment.py**
  - Cash-like payment with receiver returning change.
  - Final wallet balances/tokens after payment.

- **test_reconciliation.py**
  - Reconciliation accepts first valid spend and rejects second duplicate spend.

- **test_transfer_protocol.py**
  - Two-phase channel transfer simulation from sender wallet to receiver wallet.

- **test_offline_cbdc_poc.py**
  - Alternate offline/bundle stack:
    - sign/verify roundtrip,
    - whole-token bundle payment behavior,
    - replay rejection,
    - expiry rejection,
    - reconciliation double-spend detection.

- **tests/mobile/test_ble_flow.py**
  - BLE stub connection and message exchange handshake.

---

## 5) Remaining Work

The following items are incomplete, partial, or absent in the current repository:

- **Unified package architecture (`dpc/`)**
  - Expected namespace/package root not yet implemented.

- **Single canonical model enforcement**
  - Two parallel stacks still coexist (`token_model`/`wallet.py` and `poc_models`/`offline_wallet.py`).

- **Atomic payment sessions across all paths**
  - Canonical cash session is atomic, but bundle/offline path does not implement equivalent two-way atomic payment+change sessioning.

- **Rollback protection consistency**
  - Rollback exists in canonical `PaymentSession` and `Wallet.receive_token`; not uniformly formalized across all flows.

- **Multi-hop transfer routing**
  - No route discovery/pathfinding; only direct peer transfer simulation.

- **BLE integration (production-grade)**
  - Only in-memory BLE stub exists; no real Bluetooth transport integration.

- **Secure key storage**
  - Keys are held in memory/test keystores; no hardware-backed or encrypted-at-rest key management.

- **Privacy mechanisms**
  - No anonymity/privacy-preserving protocol layer (e.g., unlinkability, blinded credentials, private transfer metadata).

- **Dependency robustness in CI/runtime**
  - Most tests rely on `cryptography`; when absent, major suites are skipped.

---

## 6) Implementation Status Table

| Component               | Status      |
| ----------------------- | ----------- |
| Repository Architecture | Implemented |
| Token Model             | Completed   |
| Crypto Infrastructure   | Completed   |
| Wallet Engine           | Implemented |
| Payment Protocol        | Implemented |
| Cash-Like Payment Model | Implemented |
| Issuer Reconciliation   | Implemented |
| Simulated Channel       | Implemented |
| Demo Script             | Implemented |
| Automated Tests         | Implemented |

---

## 7) Summary

The repository currently implements a working offline-CBDC proof-of-concept with clear core capabilities: signed bearer tokens, transfer-chain validation, wallet transfer handling, cash-like change return, and reconciliation with double-spend detection. The primary gaps are architectural unification, production-grade transport/security, and advanced protocol features.
