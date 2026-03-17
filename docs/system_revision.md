# Digital Pocket Cash (DPC) – System Revision Report

## Overview

This report provides an implementation audit of the current DPC repository state. It identifies the production-relevant architecture used for evaluation, distinguishes legacy/experimental paths, and documents implemented security and protocol properties in a thesis-ready format.

## Master's-Level Architectural and Implementation Synthesis

### Part I: System Architecture and Design

The proposed offline digital payment system replicates the autonomy and usability of pocket cash while preserving the cryptographic security and auditability of digital currency systems. The architecture follows a **dual-layer design**:

- an **online settlement layer** (issuer/reconciliation)
- an **offline peer-to-peer layer** (local wallet exchange over short-range transport abstractions)

#### 1) Intermittently Offline Operating Model

The system is intentionally designed for intermittent connectivity. Value may circulate device-to-device offline during a payment window, while final settlement is deferred until wallets synchronize with the issuer-side reconciliation service.

This allows local circulation (`Wallet A → Wallet B → Wallet C`) without immediate central approval, while still supporting eventual consistency and fraud resolution once connectivity returns.

#### 2) Core Logical Components

- **Token Manager (digital cash analog)**
  - Creates issuer-signed bearer-style tokens with fixed denominations.
  - Denomination-first design enables exact composition of value and mirrors physical notes.

- **Transaction Verifier (decentralized trust)**
  - Performs local signature and chain-of-custody checks during P2P exchange.
  - Uses wallet-local state tracking (UTR/STR style accounting) to prevent honest local re-use.

- **Banking Interface / Reconciliation Engine**
  - Processes uploaded transfer histories after reconnection.
  - Detects transfer-chain forks (double spends), applies policy limits, and finalizes settlement.

### Part II: System Implementation (PoC)

The proof-of-concept implementation focuses on protocol correctness, cryptographic integrity, and deterministic state transitions in Python 3.10.

#### 1) Cryptographic Foundation

- Ed25519 signatures are used for issuance and transfer authorization.
- SHA-256-backed identifiers and deterministic payload serialization provide tamper evidence.
- Compact key/signature artifacts make the model suitable for short-range transport constraints.

#### 2) Token and Transfer Data Models

Tokens encode identity, denomination, issuer context, and a signature proving issuance authenticity. Transfers bind payer authorization to token identity and the prior transfer state, preserving transitivity for offline forwarding.

#### 3) Wallet State Management and Atomicity

Wallet behavior enforces a local "cash leaves the purse" rule:

- spendable records are selected from local unspent state
- once signed for payment, selected records leave spendable inventory atomically
- receiving wallets validate and only commit valid records

This minimizes honest-user double spends and guarantees local consistency.

#### 4) Multi-Token Payment and Change Handling

Payments are executed as grouped value exchange:

- sender composes required value from available denominations
- receiver validates the whole payment atomically
- if overpaid, receiver returns change from its own holdings

This preserves real-world cash semantics and avoids offline token "splitting" assumptions.

#### 5) Offline Handshake Pattern

The local exchange model uses a staged protocol:

1. Session establishment and anti-replay context binding.
2. Transfer payload exchange, cryptographic validation, and signed receipt acknowledgement.

#### 6) Double-Spend Risk Management and Reconciliation

Offline systems cannot fully prevent malicious cloned-wallet behavior in real time; instead, they **bound risk** and provide **post-facto detection**.

- Offline caps constrain exposure (value thresholds, hop/policy limits, expiry).
- Reconciliation accepts first valid spend chain and rejects conflicting forks.
- Signature trails preserve forensic attribution.

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

## Summary

The repository contains a functional canonical implementation for evaluation: transfer-chain tokens, wallet transfer handling, atomic payment-with-change sessions, and issuer-side reconciliation. Legacy modules remain available for experimentation but are not part of the primary system path.
