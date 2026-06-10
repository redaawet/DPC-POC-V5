# Digital Pocket Cash PoC

Digital Pocket Cash (DPC) is a software-only proof-of-concept for offline cryptocurrency-style pocket cash payments. It simulates Bluetooth Low Energy proximity transfers with direct Python calls while keeping the important security pieces real: Ed25519 signatures, X25519-derived session keys, ChaCha20-Poly1305 authenticated encryption, SHA-256 transfer chains, policy checks, proxy synchronization, and issuer reconciliation.

## Install

```powershell
pip install -r requirements.txt
```

## Run Tests

```powershell
python tests/run_all.py
```

Run an individual scenario:

```powershell
python tests/t1_max_hops.py
```

## Security Model

The seven-layer security model combines issuer-signed token authenticity, Ed25519 transfer authorization, chained SHA-256 transfer records, replay-resistant nonces, offline policy limits for hop count/value/balance/TTL, authenticated encrypted BLE sessions, and first-valid-claim reconciliation that flags double-spend conflicts. Private keys remain only in wallet instance memory and are never serialized.

## BLE Note

BLE is simulated in this PoC. A production mobile implementation would replace `BLEChannel` with Android BLE GATT APIs while keeping the same payload serialization, authenticated encryption, wallet policy, and reconciliation semantics.

---

## Demonstration Guide

### Quick Start: Run All 8 Test Scenarios

```bash
python tests/run_all.py
```

This executes all functional tests and prints a summary table showing which security features are enforced:

```
+------+-------------------------------------------+--------+
| Test | Objective                                 | Result |
+------+-------------------------------------------+--------+
| T1   | Max offline hops enforcement              | PASS   |
| T2   | Wallet balance cap                        | PASS   |
| T3   | Single-transaction value cap              | PASS   |
| T4   | Token TTL expiry                          | PASS   |
| T5   | Proxy synchronization (TTL reset)         | PASS   |
| T6   | Token lifecycle reset (circular spend)    | PASS   |
| T7   | Swap protocol - change generation         | PASS   |
| T8   | Double-spend prevention (first claim)     | PASS   |
+------+-------------------------------------------+--------+
All 8/8 tests passed.
```

### Individual Test Demonstrations

Each test file can be run independently to explore a specific security feature:

#### **T1: Hop Limit Enforcement**
```bash
python tests/t1_max_hops.py
```
**What it demonstrates:**  
Tokens can only be transferred offline 7 times (max_offline_hops). The 8th attempt is rejected.  
**Key output:** Shows hop_count incrementing and error "Hop limit reached" on overflow.

---

#### **T2: Wallet Balance Cap**
```bash
python tests/t2_balance_cap.py
```
**What it demonstrates:**  
A wallet cannot hold more than 10,000 ETB total (max_wallet_balance_etb). Incoming transfers that would exceed the cap are rejected.  
**Key output:** Shows balance 9,500 ETB, incoming 600 ETB rejected with "Exceeds max wallet balance".

---

#### **T3: Transaction Value Cap**
```bash
python tests/t3_tx_value_cap.py
```
**What it demonstrates:**  
Single offline transactions are capped at 1,000 ETB (max_transaction_value_etb) to limit fraud exposure.  
**Key output:** Shows 1,200 ETB transfer attempt rejected with "Transaction exceeds offline pocket cash limits".

---

#### **T4: Token TTL Expiry**
```bash
python tests/t4_ttl_expiry.py
```
**What it demonstrates:**  
Tokens expire after 7 days (604,800 seconds). Attempting to transfer an 8-day-old token fails.  
**Key output:** Shows timestamp check and error "Token expired".

---

#### **T5: Proxy Synchronization**
```bash
python tests/t5_proxy_sync.py
```
**What it demonstrates:**  
An offline device (no network for 6 days) stays valid when an online peer relays a signed heartbeat to the issuer. The TTL countdown resets without the device going online.  
**Key output:** Shows heartbeat verification and sync_registry update on the ledger.

---

#### **T6: Lifecycle Reset on Return**
```bash
python tests/t6_lifecycle_reset.py
```
**What it demonstrates:**  
When a token returns to its original owner (circular spend: A→B→C→A), the hop_count resets to 0, treating it as fresh cash.  
**Key output:** Shows "Detected my key at root. Resetting hop count to 0."

---

#### **T7: Swap Protocol (Change Generation)**
```bash
python tests/t7_swap_change.py
```
**What it demonstrates:**  
A peer-to-peer swap protocol allows making change without a centralized entity. Alice pays Bob 15 ETB using a 20 ETB token; Bob returns 5 ETB in change.  
**Key output:** Shows dual transfers and "Swap complete. Payer net: -15 ETB, Payee net: +15 ETB".

---

#### **T8: Double-Spend Prevention**
```bash
python tests/t8_double_spend.py
```
**What it demonstrates:**  
The issuer ledger uses a "first valid claim" rule. If a token is submitted twice (by two different merchants), the second submission is rejected and the attacker flagged.  
**Key output:** Shows first merchant accepted, second rejected with "Token already spent", and attacker pubkey flagged as suspicious.

---

### Understanding the Output

Each test prints annotated output with actor prefixes:
- `[Alice]`, `[Bob]`, `[Carol]` — wallet holders
- `[BLE]` — simulated Bluetooth channel (shows payload sizes, direction, encryption)
- `[Ledger]` — issuer reconciliation engine
- `[Error]` — validation failures (expected in tests)
- `[TEST Tn]` — test result (PASS/FAIL with reason)

Example run:
```
[BLE] A->B | 1311 bytes transmitted
[BLE] 315158ed -> dfd7fb14 | 500 ETB | hop_count=7
[Bob] Token nonce updated to 7.
[T1] PASS: hop limit enforced
```

---

### Exploring the Code

#### **To understand the transfer chain:**
- Look at `dpc/transfer.py::build_tx_payload()` — constructs the canonical transaction
- Look at `dpc/transfer.py::compute_chain_hash()` — chains H_n = SHA-256(Tx_n ‖ H_{n-1})
- Look at `dpc/transfer.py::verify_transfer_chain()` — validates the entire chain

#### **To understand policy enforcement:**
- Look at `dpc/models.py::PolicyConfig` — defines the 7 limit parameters
- Look at `dpc/transfer.py::build_transfer()` — checks all 5 pre-transfer conditions

#### **To understand double-spend prevention:**
- Look at `dpc/reconciliation.py::IssuerLedger::submit_token()` — first-valid-claim logic
- Look at `dpc/reconciliation.py::is_flagged()` — suspicious key detection

#### **To understand encryption:**
- Look at `dpc/crypto.py::derive_session_key()` — X25519 ECDH + HKDF-SHA256
- Look at `dpc/ble_sim.py::BLEChannel` — wraps payloads with ChaCha20-Poly1305

---

### Key Security Properties Demonstrated

1. **Authenticity** (T1–T8): Ed25519 signatures on every transfer and token issuance
2. **Chain Integrity** (T6–T8): SHA-256 chained hashes prevent token tampering
3. **Replay Resistance** (T5–T8): Nonces in each transfer prevent re-submission
4. **Policy Enforcement** (T1–T4): Hop, balance, value, and TTL limits enforced offline
5. **Proxy Authority** (T5): Delegated sync without private key exposure
6. **Circular Spend Reset** (T6): Original owner can reuse tokens as fresh cash
7. **Peer Change Generation** (T7): No central entity needed for making change
8. **First-Valid-Claim** (T8): Double-spend detection and attacker flagging at reconciliation time

---

### Extending the PoC

To add custom scenarios:
1. Create `tests/t9_custom.py` with a `run()` function
2. Import helpers: `from helpers import mint_direct, result_line`
3. Create wallets: `issuer = Wallet()`, `alice = Wallet()`
4. Use the BLE channel for transfers: `BLEChannel(a, b).execute_transfer(...)`
5. Return `result_line(name, passed, reason)` with a boolean result
