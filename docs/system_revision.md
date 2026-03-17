# Digital Pocket Cash (DPC) – System Revision Report

## Overview

This report provides an implementation audit of the current DPC repository state. It identifies the production-relevant architecture used for evaluation, distinguishes legacy/experimental paths, and documents implemented security and protocol properties in a thesis-ready format.

## Canonical Implementation Path

Two implementation paths currently coexist in the repository, but only one is treated as the primary architecture for system evaluation.

### Canonical stack used by the system

- **Token layer**
  - `token/token_model.py`
  - `token/transfer_chain.py`
- **Wallet layer**
  - `wallet/wallet.py`
- **Protocol layer**
  - `protocol/payment_session.py`
  - `protocol/cash_payment.py`
- **Issuer layer**
  - `issuer/issuer.py`
  - `issuer/reconciliation.py`

### Legacy or experimental components (non-canonical)

The following components are retained for experimentation and comparative development, but they are **not required for the main payment protocol**:

- `token/poc_models.py`
- `wallet/offline_wallet.py`
- `protocol/network_simulator.py`
- `issuer/reconciliation_server.py`

## End-to-End System Execution Flow

The canonical payment lifecycle is executed as follows:

1. Issuer mints tokens.
2. Wallet receives tokens.
3. Sender selects tokens.
4. Sender initiates payment session.
5. Receiver validates tokens.
6. Receiver calculates change.
7. Receiver sends change tokens.
8. Both wallets update state.
9. Issuer reconciliation later detects double spends.

**Sequence:** `Issuer → Wallet A → Wallet B → Wallet A → Issuer`

## Repository Structure Audit

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

- The `dpc/` namespace is not present as a physical directory.
- Core domains are implemented as top-level Python packages.
- `mobile/` currently exposes a BLE stub for testing, not production BLE transport.

### Module inventory and purpose

- **crypto/**
  - `crypto_utils.py`: Ed25519 helpers with `cryptography` backend and OpenSSL CLI fallback.
  - `signatures.py`: Ed25519 key/sign/verify helpers using base64 key material.
- **token/**
  - `token_model.py`: canonical token model with immutable token identity/value and transfer-chain validation.
  - `transfer_chain.py`: transfer record model with deterministic serialization and signatures.
  - `poc_models.py`: alternate PoC token/transfer/payment-bundle models (non-canonical).
- **wallet/**
  - `wallet.py`: canonical UTR/STR wallet with token selection, send/receive, and sync.
  - `offline_wallet.py`: alternate offline wallet with policy checks and replay controls (non-canonical).
- **protocol/**
  - `payment_session.py`: atomic payment + change session with rollback.
  - `cash_payment.py`: wrapper for session execution.
  - `transfer_protocol.py`: two-phase discovery and transfer simulation.
  - `network_simulator.py`: local bundle send helper for non-canonical path.
  - `policy.py`: policy limits and expiry utility.
- **issuer/**
  - `issuer.py`: issuer minting/signing logic.
  - `reconciliation.py`: canonical transfer-chain reconciliation.
  - `reconciliation_server.py`: non-canonical bundle settlement and double-spend checks.
- **mobile/**
  - `ble_adapter_stub.py`: in-memory BLE adapter stub used by tests.
- **scripts/**
  - `run_demo.py`: end-to-end demonstration script for canonical wallet/session flow.
- **tests/**
  - Unit/integration tests for crypto, token chain, wallet behavior, payment sessioning, transfer simulation, reconciliation, and BLE stub interaction.

## Implemented Security Properties

- **Token Authenticity**
  Issuer signatures guarantee that accepted tokens originate from the issuer and are valid.

- **Transfer Authorization**
  Each transfer must include a valid signature from the previous owner in the transfer chain.

- **Double Spend Detection**
  Issuer reconciliation accepts the first valid spend and rejects duplicate subsequent spends.

- **Atomic Payment Session**
  Payment and change exchange occur within a controlled session that supports rollback on failure.

- **Token Integrity**
  Token value and token ID are immutable after issuance in the canonical token model.

## Research Contribution Mapping

| Thesis Contribution                | Implementation                |
| ---------------------------------- | ----------------------------- |
| Offline cash-like digital currency | token_model + wallet transfer |
| Peer-to-peer payment protocol      | payment_session               |
| Double-spend detection mechanism   | reconciliation                |
| Offline payment simulation         | transfer_protocol             |

## Test Coverage Review

### Present test modules

- `tests/test_crypto.py`
- `tests/test_token.py`
- `tests/test_wallet_flow.py`
- `tests/test_cash_payment.py`
- `tests/test_reconciliation.py`
- `tests/test_transfer_protocol.py`
- `tests/test_offline_cbdc_poc.py`
- `tests/mobile/test_ble_flow.py`

### Coverage summary

- Crypto signing and verification behavior.
- Token issuance and transfer-chain validation, including tamper rejection.
- Wallet UTR/STR lifecycle and atomic receive rollback.
- Cash-like payment flow with change return.
- Reconciliation first-spend acceptance and duplicate rejection.
- Simulated transfer protocol behavior.
- Legacy offline bundle flow behavior.
- BLE stub messaging handshake.

## Remaining Work

- Unify namespace architecture under a single `dpc/` package.
- Remove ambiguity between canonical and legacy stacks through explicit module deprecation or isolation.
- Add production BLE transport integration.
- Add secure key storage (hardware-backed or encrypted-at-rest).
- Add privacy-preserving transfer mechanisms.
- Add multi-hop routing/pathfinding.

## System Maturity Level

**Research Prototype**

The system demonstrates feasibility of offline digital cash using transfer-chain tokens, but it does not yet include production-grade infrastructure such as secure hardware key storage, real BLE networking, or privacy-preserving transaction mechanisms.

## Implementation Status Table

| Component                  | Status          |
| -------------------------- | --------------- |
| Cryptographic primitives   | Completed       |
| Token transfer-chain model | Completed       |
| Wallet engine              | Completed       |
| Cash-like payment protocol | Completed       |
| Issuer reconciliation      | Completed       |
| Offline payment simulation | Completed       |
| BLE transport layer        | Prototype       |
| Privacy protection         | Not implemented |
| Multi-hop routing          | Not implemented |

## Summary

The repository contains a functional canonical implementation for evaluation: transfer-chain tokens, wallet transfer handling, atomic payment-with-change sessions, and issuer-side reconciliation. Legacy modules remain available for experimentation but are not part of the primary system path.
