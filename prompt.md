# Digital Pocket Cash (DPC) — Full PoC Implementation Prompt

> **Target AI Coding Agent**: Claude Code / Codex  
> **Source**: *"Bluetooth-Enabled Offline Cryptocurrency Payments for Automated Pocket Cash Transactions"* — Awet Teka Reda, M.Sc. Thesis, Mekelle University, EiT-M, May 2026  
> **Runtime**: Python 3.10+  
> **Goal**: Implement the complete, runnable proof-of-concept described in the thesis, including all eight scripted test scenarios (T1–T8) with pass/fail output.

---

## 0. Context & Constraints

You are implementing the **Digital Pocket Cash (DPC)** system: a software-only simulation of a Bluetooth Low Energy offline cryptocurrency payment architecture.  
The BLE radio layer is **abstracted** — all proximity communication is simulated by direct Python function calls.  
**No real network, no actual BLE hardware, no blockchain node** is required.  
All cryptographic operations must be **real** (not mocked): use the `cryptography` library for Ed25519 and X25519; use `hashlib` for SHA-256.

---

## 1. Project Structure

Create the following file tree exactly:

```
dpc_poc/
├── README.md
├── requirements.txt
├── dpc/
│   ├── __init__.py
│   ├── crypto.py          # Ed25519, X25519, ChaCha20-Poly1305, SHA-256 utilities
│   ├── models.py          # Token, TransferRecord, WalletState, PolicyConfig dataclasses
│   ├── wallet.py          # Wallet class — key gen, UTR, coin selection, transfer construction
│   ├── transfer.py        # Transfer chain logic — build, sign, verify
│   ├── ble_sim.py         # Simulated BLE channel — connect, send_payload, close
│   ├── reconciliation.py  # IssuerLedger — submit, conflict detection, first-valid-claim
│   └── proxy_sync.py      # ProxySync — heartbeat relay, TTL reset
└── tests/
    ├── __init__.py
    ├── run_all.py         # Runs T1–T8 in sequence, prints PASS/FAIL table
    ├── t1_max_hops.py
    ├── t2_balance_cap.py
    ├── t3_tx_value_cap.py
    ├── t4_ttl_expiry.py
    ├── t5_proxy_sync.py
    ├── t6_lifecycle_reset.py
    ├── t7_swap_change.py
    └── t8_double_spend.py
```

---

## 2. requirements.txt

```
cryptography>=42.0.0
pytest>=8.0.0
```

---

## 3. Module Specifications

### 3.1 `dpc/models.py`

Define all data structures as Python `dataclasses`. Use `field(default_factory=...)` for mutable defaults.

```python
from dataclasses import dataclass, field
from typing import Optional, List
import time

@dataclass
class PolicyConfig:
    max_offline_hops: int = 7
    max_wallet_balance_etb: float = 10_000.0
    max_transaction_value_etb: float = 1_000.0
    token_ttl_seconds: int = 604_800   # 7 days
    
@dataclass
class Token:
    token_id: str                    # UUID4 hex string
    denomination: float              # Value in ETB
    issuer_pubkey_hex: str           # Hex-encoded Ed25519 public key of the issuer
    issued_at: float                 # Unix timestamp, issuer-signed (unforgeable lower bound)
    issuer_signature_hex: str        # Hex Ed25519 signature over (token_id + issuer_pubkey + issued_at + denomination)
    owner_pubkey_hex: str            # Current owner's hex Ed25519 public key
    hop_count: int = 0               # Number of times transferred offline
    transfer_history: List[str] = field(default_factory=list)  # Ordered list of hex pubkeys (issuer→current owner)
    chain_hash: str = ""             # SHA-256 hex of the most recent transfer hash H_n; empty = genesis

@dataclass
class TransferRecord:
    token_id: str
    prev_owner_pubkey_hex: str
    next_owner_pubkey_hex: str
    amount: float
    nonce_hex: str              # 128-bit CSPRNG hex nonce (replay prevention)
    chain_hash: str             # H_n = SHA-256(Tx_n ‖ H_{n-1})
    signature_hex: str          # Ed25519 signature of chain_hash by prev_owner
    timestamp: float            # Local timestamp of the transfer

@dataclass
class SyncHeartbeat:
    wallet_pubkey_hex: str
    last_sync_timestamp: float
    token_ids: List[str]
    signature_hex: str          # Ed25519 signature by wallet owner over (pubkey + timestamp + token_ids)

@dataclass
class WalletState:
    owner_pubkey_hex: str
    # UTR: token_id -> Token
    unspent_tokens: dict = field(default_factory=dict)
    # Spent nonces this session: set of (token_id, nonce_hex)
    spent_nonces: set = field(default_factory=set)
    last_sync_timestamp: float = field(default_factory=time.time)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
```

---

### 3.2 `dpc/crypto.py`

Implement all cryptographic primitives. All methods are **static or module-level functions**.

```python
# Required functions (implement each fully):

def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key_bytes_32, public_key_bytes_32)."""

def ed25519_sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """Returns 64-byte Ed25519 signature."""

def ed25519_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Returns True if signature is valid, False otherwise. Never raises on invalid sig."""

def ed25519_pubkey_to_hex(public_key_bytes: bytes) -> str:
    """Hex-encode a 32-byte public key."""

def hex_to_pubkey_bytes(hex_str: str) -> bytes:
    """Decode hex string to 32-byte key bytes."""

def sha256_hex(*parts: bytes) -> str:
    """Concatenate all parts and return SHA-256 hex digest."""

def generate_nonce_hex() -> str:
    """Return a 128-bit (32 hex chars) CSPRNG nonce."""

def ed25519_to_x25519_private(ed25519_private_bytes: bytes) -> bytes:
    """Convert Ed25519 private key to X25519 private key via birational equivalence."""

def ed25519_to_x25519_public(ed25519_public_bytes: bytes) -> bytes:
    """Convert Ed25519 public key to X25519 public key."""

def derive_session_key(
    my_ed25519_private: bytes,
    peer_ed25519_public: bytes,
    nonce: bytes
) -> bytes:
    """
    1. Convert both keys to X25519 form.
    2. Perform ECDH to get shared_secret.
    3. Return HKDF-SHA256(shared_secret, salt=nonce, info=b"DPC-session", length=32).
    """

def chacha20_poly1305_encrypt(key: bytes, nonce_12: bytes, plaintext: bytes) -> bytes:
    """Encrypt with ChaCha20-Poly1305. Returns ciphertext+tag (16-byte tag appended)."""

def chacha20_poly1305_decrypt(key: bytes, nonce_12: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Decrypt. Raises ValueError if authentication fails."""
```

**Implementation notes:**
- Use `cryptography.hazmat.primitives.asymmetric.ed25519` for Ed25519.
- For X25519 conversion: use `cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes()` after applying the standard clamping/bit-manipulation to the SHA-512 hash of the Ed25519 seed.
- Use `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305` for AEAD.
- Use `cryptography.hazmat.primitives.kdf.hkdf.HKDF` for key derivation.
- `os.urandom(16)` for nonce generation.

---

### 3.3 `dpc/transfer.py`

Implements the three-step transfer chain defined in the thesis (Section 3.5.2).

```python
def build_tx_payload(
    token_id: str,
    next_owner_pubkey_hex: str,
    amount: float,
    nonce_hex: str
) -> bytes:
    """
    Construct the canonical transaction payload:
    Tx_n = Token_ID ‖ NextOwner_PK ‖ Amount ‖ Nonce
    Encode amount as big-endian IEEE 754 double (8 bytes).
    Concatenate as bytes and return.
    """

def compute_chain_hash(tx_payload: bytes, prev_chain_hash: str) -> str:
    """
    H_n = SHA-256(Tx_n ‖ H_{n−1})
    prev_chain_hash is hex string; use empty bytes b"" for genesis transfer.
    Returns hex string.
    """

def sign_transfer(
    payer_private_key_bytes: bytes,
    chain_hash_hex: str
) -> str:
    """
    Signature_n = Ed25519_Sign(Payer_SK, H_n)
    Returns hex signature string.
    """

def verify_transfer_chain(token: Token, transfer_record: TransferRecord) -> bool:
    """
    Full chain verification:
    1. Recompute Tx payload from record fields.
    2. Recompute H_n = SHA-256(Tx ‖ prev_hash).
    3. Verify signature against prev_owner's public key.
    4. Check nonce not replayed (caller must check UTR).
    5. Return True only if all checks pass.
    """

def build_transfer(
    token: Token,
    payer_private_key_bytes: bytes,
    payer_pubkey_hex: str,
    recipient_pubkey_hex: str,
    amount: float,
    policy: PolicyConfig,
    wallet_state: WalletState
) -> tuple[TransferRecord, Token]:
    """
    Full transfer construction pipeline:
    
    Pre-transfer checks (raise ValueError with descriptive message on failure):
    - token.hop_count >= policy.max_offline_hops → "Hop limit reached"
    - amount > policy.max_transaction_value_etb → "Transaction exceeds offline pocket cash limits"
    - amount > token.denomination → "Insufficient token value"
    - token is expired (time.time() - token.issued_at > policy.token_ttl_seconds) → "Token expired"
    
    If checks pass:
    1. Generate nonce_hex = generate_nonce_hex().
    2. Build Tx payload.
    3. Compute H_n using token.chain_hash as prev.
    4. Sign H_n.
    5. Construct TransferRecord.
    6. Clone token, update owner_pubkey_hex, hop_count+1, chain_hash, append to transfer_history.
    7. Return (TransferRecord, updated_token).
    """
```

---

### 3.4 `dpc/wallet.py`

The `Wallet` class manages the full lifecycle of a user's DPC wallet.

```python
class Wallet:
    def __init__(self, policy: PolicyConfig = None):
        """
        Generate a fresh Ed25519 keypair.
        Initialize WalletState with empty UTR, current timestamp, given policy.
        Store private_key_bytes (in memory only — TEE abstracted).
        """
    
    @property
    def pubkey_hex(self) -> str: ...
    
    @property
    def balance(self) -> float:
        """Sum of all denominations in UTR."""
    
    def receive_token(self, token: Token, transfer_record: TransferRecord) -> None:
        """
        Validate the incoming token:
        1. Verify transfer chain (call verify_transfer_chain).
        2. Check nonce not replayed (token_id, nonce_hex) in spent_nonces.
        3. Check balance cap: self.balance + token.denomination <= max_wallet_balance_etb.
           Raise ValueError("Exceeds max wallet balance") if violated.
        4. Verify the incoming token.owner_pubkey_hex == self.pubkey_hex.
        5. Add (token_id, nonce_hex) to spent_nonces.
        6. Add token to UTR.
        """
    
    def send_token(self, token_id: str, recipient_pubkey_hex: str, amount: float) -> tuple[TransferRecord, Token]:
        """
        1. Look up token in UTR. Raise if not found.
        2. Check for lifecycle reset: if self.pubkey_hex appears in token.transfer_history (excluding current owner),
           reset token.hop_count = 0 and log "Detected own key in history. Resetting hop count to 0."
        3. Call build_transfer() from transfer.py.
        4. Remove token from UTR (it's been spent).
        5. Return (TransferRecord, new_token_for_recipient).
        """
    
    def get_token_for_swap(self, amount: float) -> Optional[Token]:
        """
        Coin selection: find the smallest UTR token with denomination >= amount.
        Returns None if no such token exists.
        Used for change generation in T7.
        """
    
    def issue_token(self, denomination: float) -> Token:
        """
        Issuer-only: mint a new token.
        Sign (token_id + issuer_pubkey + issued_at + denomination) with self.private_key.
        Set owner = self.pubkey_hex (issuer holds it until transferred).
        hop_count = 0, transfer_history = [self.pubkey_hex].
        chain_hash = "" (genesis).
        """
    
    def deposit_to_issuer(self, token_id: str) -> Token:
        """Remove token from UTR and return it for reconciliation submission."""
    
    def get_sync_heartbeat(self) -> SyncHeartbeat:
        """
        Build a signed SyncHeartbeat containing all current token_ids.
        Signature covers: pubkey_hex + str(last_sync_timestamp) + sorted token_ids joined.
        """
```

---

### 3.5 `dpc/ble_sim.py`

Simulates the BLE channel for the PoC. No actual networking.

```python
class BLEChannel:
    """
    Simulates a BLE link between exactly two Wallet instances.
    Optionally applies session-level encryption using derive_session_key + ChaCha20-Poly1305.
    """
    
    def __init__(self, wallet_a: Wallet, wallet_b: Wallet, encrypt: bool = True):
        """
        If encrypt=True, derive a shared session key from X25519 ECDH using both wallets' keys.
        Use os.urandom(12) as the 12-byte ChaCha20 nonce for this session.
        Store session_key and session_nonce_12.
        """
    
    def transmit(self, payload_bytes: bytes, direction: str = "A→B") -> bytes:
        """
        If encrypt=True, encrypt payload_bytes before 'transmission', then decrypt on the other side.
        Log: f"[BLE] {direction} | {len(payload_bytes)} bytes transmitted"
        Return the decrypted bytes (simulating successful delivery).
        If authentication fails, raise ValueError("BLE session authentication failed").
        """
    
    def execute_transfer(
        self,
        sender_wallet: Wallet,
        recipient_wallet: Wallet,
        token_id: str,
        amount: float
    ) -> tuple[TransferRecord, Token]:
        """
        Full BLE payment handshake:
        1. sender_wallet.send_token(token_id, recipient_wallet.pubkey_hex, amount) → (record, new_token).
        2. Serialize (record, new_token) to bytes; transmit through BLE channel.
        3. Deserialize on recipient side.
        4. recipient_wallet.receive_token(new_token, record).
        5. Print summary: sender pubkey[:8], recipient pubkey[:8], amount, hop_count.
        6. Return (record, new_token).
        """
    
    def execute_swap(
        self,
        payer_wallet: Wallet,
        payee_wallet: Wallet,
        payer_token_id: str,
        owed_amount: float
    ) -> None:
        """
        Swap protocol for T7 (change generation):
        1. payer sends payer_token to payee (full denomination).
        2. payee selects a change token from UTR for (payer_token.denomination - owed_amount).
        3. payee sends change token back to payer in the same handshake.
        4. Print: f"Swap complete. Payer net: -{owed_amount} ETB, Payee net: +{owed_amount} ETB"
        """
```

---

### 3.6 `dpc/reconciliation.py`

The issuer's central ledger. Simulates CBDC reconciliation.

```python
class IssuerLedger:
    """
    Simulates the reconciliation engine at the CBDC issuer / central bank.
    Maintains a first-valid-claim registry: token_id → owner_pubkey_hex.
    """
    
    def __init__(self):
        self.registry: dict[str, str] = {}         # token_id → current owner pubkey
        self.suspicious_keys: set[str] = set()     # flagged public keys
        self.submission_log: list[dict] = []        # full audit trail
    
    def submit_token(self, token: Token, submitter_pubkey_hex: str) -> dict:
        """
        Process a token redemption/reconciliation submission.
        
        Returns a result dict:
        {
            "token_id": str,
            "accepted": bool,
            "owner": str or None,
            "reason": str   # "accepted", "already spent", "invalid signature", etc.
        }
        
        Logic:
        1. Verify issuer_signature on token (tamper detection).
        2. If token.token_id not in registry: accept. registry[token_id] = submitter.
        3. Else if registry[token_id] == submitter: idempotent re-submission → accepted.
        4. Else: CONFLICT. 
           - Log both the accepted owner and the conflicting submitter.
           - Add submitter_pubkey_hex to suspicious_keys.
           - Mark the ORIGINAL owner (the one who passed to the double-spender) for investigation.
           - Return accepted=False, reason="Token already spent".
        5. Append to submission_log.
        """
    
    def submit_batch(self, tokens: list[Token], submitter_pubkey_hex: str) -> list[dict]:
        """Submit multiple tokens at once. Returns list of result dicts."""
    
    def get_balance(self, owner_pubkey_hex: str) -> float:
        """Sum denomination of all tokens in registry owned by given pubkey."""
    
    def is_flagged(self, pubkey_hex: str) -> bool:
        """Returns True if pubkey is in suspicious_keys."""
    
    def print_report(self) -> None:
        """Print a formatted table of all submissions and their outcomes."""
```

---

### 3.7 `dpc/proxy_sync.py`

Implements the delegated proxy synchronization mechanism (Section 3.4.3).

```python
class ProxySync:
    """
    Allows an online peer to relay a sync heartbeat to the issuer ledger
    on behalf of an offline device, resetting the TTL countdown.
    """
    
    def __init__(self, issuer_ledger: IssuerLedger):
        self.ledger = issuer_ledger
        self.sync_registry: dict[str, float] = {}   # pubkey_hex → last_sync_timestamp
    
    def relay_heartbeat(self, heartbeat: SyncHeartbeat, relay_wallet: Wallet) -> bool:
        """
        1. Verify the heartbeat's Ed25519 signature (ensures the relay peer cannot forge it).
        2. If valid, update sync_registry[heartbeat.wallet_pubkey_hex] = current time.
        3. Print: f"[Ledger] Updated {heartbeat.wallet_pubkey_hex[:8]}...last_sync to {timestamp}"
        4. Return True on success, False on invalid signature.
        
        Security note: the relay wallet CANNOT alter the heartbeat contents —
        any tampering invalidates the signature. A malicious relay can only
        refuse to relay (liveness failure), not forge a sync.
        """
    
    def get_effective_last_sync(self, wallet_pubkey_hex: str) -> float:
        """
        Returns the most recent known sync timestamp for the wallet.
        Falls back to 0 if never synced.
        """
    
    def is_token_valid(
        self,
        token: Token,
        wallet_pubkey_hex: str,
        policy: PolicyConfig
    ) -> bool:
        """
        Token is valid if:
        (current_time - issued_at) < ttl AND
        (current_time - get_effective_last_sync(wallet_pubkey_hex)) < ttl
        """
```

---

## 4. Test Scenarios T1–T8

Each test file is a self-contained script. Every test must:
- Print `[TEST Tn: <Name>]` header.
- Print key intermediate state (wallet balances, token nonces, error messages).
- Print `✅ PASS` or `❌ FAIL` at the end with a one-line reason.
- Raise no unhandled exceptions on pass.

---

### T1: Maximum Offline Hops Enforcement (`tests/t1_max_hops.py`)

```
Scenario:
  issuer = Wallet (issuer)
  alice  = Wallet
  bob    = Wallet

  issuer mints a 500 ETB token (token_A).
  issuer → alice: transfer token_A (hop 1).
  
  # Manually set token hop_count = 6 in Alice's UTR to simulate 6 prior transfers.
  
  alice → bob: transfer token_A (this should be the 7th hop → accepted, nonce becomes 7).
  
  # Now attempt one more transfer from bob → alice (8th hop).
  # Expect: ValueError("Hop limit reached")

Pass criteria:
  - The 7th transfer succeeds (nonce == 7).
  - The 8th transfer raises ValueError with message containing "Hop limit".
  - Print: "[Bob] Token nonce updated to 7."
  - Print: "[Error] Hop limit reached — transfer rejected as expected."
```

---

### T2: Maximum Wallet Balance Cap (`tests/t2_balance_cap.py`)

```
Scenario:
  issuer = Wallet (issuer)
  alice  = Wallet
  bob    = Wallet (starts with UTR total = 9,500 ETB via multiple pre-issued tokens)

  To set up bob's balance: issuer mints 19 tokens of 500 ETB each, transfers them all to bob
  (you may use a loop and bypass the BLE layer for setup speed, calling receive_token directly
  with minimal valid TransferRecords — or issue a single large token to bob directly).
  
  alice attempts to send bob a 600 ETB token (would bring total to 10,100 ETB).
  Expect: receive_token raises ValueError("Exceeds max wallet balance").

Pass criteria:
  - Bob's pre-setup balance == 9,500 ETB.
  - The 600 ETB receive raises ValueError containing "max wallet balance".
  - Print: "[Bob] Current balance: 9500, incoming: 600, cap: 10000"
  - Print: "[Bob] ERROR: Rejecting payment – would exceed max wallet balance."
```

---

### T3: Single-Transaction Value Cap (`tests/t3_tx_value_cap.py`)

```
Scenario:
  issuer mints a 2,000 ETB token for alice.
  alice tries to send bob 1,200 ETB.
  Expect: build_transfer raises ValueError("Transaction exceeds offline pocket cash limits").

Pass criteria:
  - ValueError raised with correct message.
  - Print the error message clearly.
```

---

### T4: Token TTL Expiry (`tests/t4_ttl_expiry.py`)

```
Scenario:
  issuer mints a token for alice.
  Manually backdate token.issued_at by 8 days (691,200 seconds):
    token.issued_at = time.time() - (8 * 24 * 3600)
  alice attempts to send to bob.
  Expect: build_transfer raises ValueError("Token expired").

Pass criteria:
  - ValueError raised with "expired" in message.
  - Print: "[Alice] Checking token timestamp (8 days old) against TTL (7d)..."
  - Print: "[Alice] ERROR: Token expired (stale offline token). Cannot create payment."
```

---

### T5: Delegated Reconciliation / Proxy Sync (`tests/t5_proxy_sync.py`)

```
Scenario:
  issuer = Wallet
  device_a = Wallet  (offline — 6 days since last sync)
  device_b = Wallet  (online peer)
  ledger = IssuerLedger
  proxy  = ProxySync(ledger)
  
  # Simulate device_a having been offline 6 days:
  device_a.state.last_sync_timestamp = time.time() - (6 * 24 * 3600)
  
  # device_a is still within 7-day TTL but day 7 is coming.
  # device_b comes online and relays device_a's heartbeat to the ledger.
  
  heartbeat = device_a.get_sync_heartbeat()
  result = proxy.relay_heartbeat(heartbeat, relay_wallet=device_b)
  
  # Confirm: proxy.sync_registry[device_a.pubkey_hex] ≈ time.time()
  # Confirm: TTL countdown is reset — device_a's tokens are still valid.

Pass criteria:
  - relay_heartbeat returns True.
  - proxy.get_effective_last_sync(device_a.pubkey_hex) is within 5 seconds of time.time().
  - Print: "[Device B] Received sync heartbeat from A."
  - Print: "[Ledger] Updated A.last_sync to current time."
  - Print: "TTL reset confirmed. Device A tokens remain active."
```

---

### T6: Token Lifecycle Reset on Return (`tests/t6_lifecycle_reset.py`)

```
Scenario:
  issuer mints token (500 ETB) for alice (hop=0).
  alice → bob (hop=1)
  bob → carol (hop=2)
  carol → alice (returning token to original owner)
  
  alice.send_token detects alice's pubkey in token.transfer_history → reset hop_count = 0.
  alice receives the token with hop_count = 0.

Pass criteria:
  - After carol → alice transfer, the token in alice's UTR has hop_count == 0.
  - Print: "[A] Token history: [A, B, C]. Detected my key at root. Resetting nonce to 0."
  - Print: "[A] Accepted token as fresh cash."
```

---

### T7: Peer-to-Peer Change Generation — Swap Protocol (`tests/t7_swap_change.py`)

```
Scenario:
  issuer mints:
    - a 20 ETB token → alice's UTR
    - a 5 ETB token  → bob's UTR
  
  alice owes bob 15 ETB but only has the 20 ETB token.
  Execute BLEChannel.execute_swap(alice, bob, token_id=<20ETB token>, owed_amount=15.0)
  
  Expected outcome:
    - alice's UTR: 5 ETB token (change received from bob)
    - bob's UTR:   20 ETB token (received from alice)
    - alice net: -15 ETB
    - bob net:   +15 ETB

Pass criteria:
  - alice.balance == 5.0
  - bob.balance == 20.0
  - Print: "Swap complete. Payer net: -15 ETB, Payee net: +15 ETB"
```

---

### T8: Double-Spending Prevention via Reconciliation (`tests/t8_double_spend.py`)

```
Scenario:
  issuer = Wallet
  alice  = Wallet  (malicious — simulated wallet clone)
  merchant_a = Wallet
  merchant_b = Wallet
  ledger = IssuerLedger()

  issuer mints TokenX (800 ETB) → alice.
  
  # Alice pays Merchant A offline:
  _, token_for_a = ble.execute_transfer(alice, merchant_a, token_X_id, 800.0)
  
  # ATTACK: Manually clone token_X from alice's state BEFORE the transfer
  # to simulate alice "cloning her wallet":
  # (Rebuild a copy of token_X as it was before the transfer, still owned by alice)
  cloned_token_X = ... # deep copy of original token before the transfer to merchant_a
  
  # Alice pays Merchant B with the cloned token:
  # Directly construct a fraudulent TransferRecord and new token
  # bypassing wallet checks (simulating a cloned/hacked wallet).
  
  # Both merchants submit to the ledger:
  result_a = ledger.submit_token(token_for_a, merchant_a.pubkey_hex)
  result_b = ledger.submit_token(cloned_token_for_b, merchant_b.pubkey_hex)
  
  ledger.print_report()

Pass criteria:
  - result_a["accepted"] == True
  - result_b["accepted"] == False
  - result_b["reason"] contains "already spent"
  - ledger.is_flagged(alice.pubkey_hex) == True
  - Print: "[Merchant A] Submitting Token TX123 to Ledger..."
  - Print: "[Ledger] Token TX123 accepted. Ownership updated (Alice→MerchantA)."
  - Print: "[Merchant B] Submitting Token TX123 to Ledger..."
  - Print: "[Ledger] ERROR: Token TX123 already spent. Rejecting transaction."
  - Print: "[Ledger] Flagging PK_Alice as suspicious."
```

---

### `tests/run_all.py`

Runs all eight tests in sequence, catches any exceptions, and prints a summary table.

```python
"""
Run all DPC functional tests T1–T8 and print a PASS/FAIL summary table.

Output format:
┌──────┬─────────────────────────────────────────┬────────┐
│ Test │ Objective                               │ Result │
├──────┼─────────────────────────────────────────┼────────┤
│ T1   │ Max offline hops enforcement            │ ✅ PASS │
│ T2   │ Wallet balance cap                      │ ✅ PASS │
│ T3   │ Single-transaction value cap            │ ✅ PASS │
│ T4   │ Token TTL expiry                        │ ✅ PASS │
│ T5   │ Proxy synchronization (TTL reset)       │ ✅ PASS │
│ T6   │ Token lifecycle reset (circular spend)  │ ✅ PASS │
│ T7   │ Swap protocol — change generation       │ ✅ PASS │
│ T8   │ Double-spend prevention (first claim)   │ ✅ PASS │
└──────┴─────────────────────────────────────────┴────────┘
All 8/8 tests passed.
"""
```

---

## 5. README.md

Must include:
1. One-paragraph description of the DPC system.
2. Install instructions: `pip install -r requirements.txt`
3. How to run all tests: `python tests/run_all.py`
4. How to run individual tests: `python tests/t1_max_hops.py`
5. Brief explanation of the seven-layer security model.
6. Note that BLE is simulated; real hardware would use Android BLE GATT API.

---

## 6. Serialization Convention

For BLE transmission, serialize `(TransferRecord, Token)` pairs as JSON using `dataclasses.asdict()`, encode to UTF-8, then encrypt with ChaCha20-Poly1305 if `encrypt=True`.  
Deserialize by decrypting, then reconstructing dataclasses from the dict.

---

## 7. Coding Standards & Constraints

- **Python 3.10+** only. Use `match/case` where appropriate.
- All functions must have **type annotations** on parameters and return types.
- Use **dataclasses** for all data models; do not use plain dicts for core data.
- Never store private key bytes in any serialized output (JSON, logs, etc.).
- Use `secrets.token_hex(16)` for token ID generation (UUID alternative).
- All `print()` statements in tests must be **prefixed with the actor** e.g. `[Alice]`, `[Bob]`, `[Ledger]`, `[BLE]`.
- The codebase must be importable as a Python package (`import dpc`).
- All 8 tests must pass with `python tests/run_all.py` producing 8/8 PASS.

---

## 8. Known Edge Cases to Handle

| Edge Case | Handling |
|---|---|
| `token.hop_count == policy.max_offline_hops` | Refuse (not >=, exactly at the cap is already the last hop that was **accepted**; one more is refused) |
| Wallet balance cap: existing balance + incoming amount > cap | Refuse even if it's exactly 1 ETB over |
| Clock manipulation: `token.issued_at` in the future | Refuse with "Invalid token: issued in the future" |
| Empty `chain_hash` (genesis token) | `H_0 = SHA-256(Tx_0 ‖ b"")` — use empty bytes for prev hash |
| Circular spend where `transfer_history` has the owner at **any** position (not only root) | Reset hop count to 0 regardless of position |
| `execute_swap` when payee has no suitable change token | Raise `ValueError("Insufficient change tokens for swap")` |

---

## 9. Security Notes for the Implementation

1. **Key material**: `private_key_bytes` lives only in Wallet instance memory. Never log it, never serialize it.
2. **Nonce uniqueness**: The `spent_nonces` set in `WalletState` must be checked BEFORE adding a token to the UTR. A nonce collision means replay → reject.
3. **Issuer signature on tokens**: Every `receive_token` call must verify the issuer's `issuer_signature_hex` by reconstructing the signed message: `token_id + issuer_pubkey_hex + str(issued_at) + str(denomination)` (UTF-8 encoded, consistent byte layout).
4. **Transfer history integrity**: `token.transfer_history` is append-only. No module outside `wallet.py`'s `send_token` should modify it.
5. **PFS note**: The session key in `BLEChannel` is never stored after the channel is closed. Each `BLEChannel` instantiation derives a fresh key.

---

## 10. Deliverables Checklist

- [ ] `dpc/crypto.py` — all 10 functions implemented and tested
- [ ] `dpc/models.py` — 5 dataclasses with correct fields
- [ ] `dpc/transfer.py` — 4 functions: build, hash, sign, verify
- [ ] `dpc/wallet.py` — Wallet class with 8 methods
- [ ] `dpc/ble_sim.py` — BLEChannel with transfer + swap methods
- [ ] `dpc/reconciliation.py` — IssuerLedger with submit + conflict detection
- [ ] `dpc/proxy_sync.py` — ProxySync with relay + TTL check
- [ ] `tests/t1_max_hops.py` through `tests/t8_double_spend.py` — all 8 scenarios
- [ ] `tests/run_all.py` — summary table showing 8/8 PASS
- [ ] `README.md` — installation and usage instructions
- [ ] `requirements.txt`

---

*This prompt is derived from the M.Sc. thesis by Awet Teka Reda, Mekelle University, EiT-M, May 2026.*
