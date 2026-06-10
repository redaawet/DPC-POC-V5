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
