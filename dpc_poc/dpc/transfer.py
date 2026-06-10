from __future__ import annotations

from dataclasses import replace
import struct
import time

from .crypto import ed25519_sign, ed25519_verify, generate_nonce_hex, hex_to_pubkey_bytes, sha256_hex
from .models import PolicyConfig, Token, TransferRecord, WalletState


def build_tx_payload(
    token_id: str,
    next_owner_pubkey_hex: str,
    amount: float,
    nonce_hex: str,
) -> bytes:
    return (
        token_id.encode("utf-8")
        + bytes.fromhex(next_owner_pubkey_hex)
        + struct.pack(">d", amount)
        + bytes.fromhex(nonce_hex)
    )


def compute_chain_hash(tx_payload: bytes, prev_chain_hash: str) -> str:
    prev = bytes.fromhex(prev_chain_hash) if prev_chain_hash else b""
    return sha256_hex(tx_payload, prev)


def sign_transfer(payer_private_key_bytes: bytes, chain_hash_hex: str) -> str:
    return ed25519_sign(payer_private_key_bytes, bytes.fromhex(chain_hash_hex)).hex()


def verify_transfer_chain(token: Token, transfer_record: TransferRecord) -> bool:
    prev_hash = ""
    if token.hop_count > 0:
        current_hash = token.chain_hash
        prev_hash = token.chain_hash
        payload = build_tx_payload(
            transfer_record.token_id,
            transfer_record.next_owner_pubkey_hex,
            transfer_record.amount,
            transfer_record.nonce_hex,
        )
        expected = compute_chain_hash(payload, token.chain_hash)
        if expected == transfer_record.chain_hash:
            prev_hash = token.chain_hash
        elif current_hash == transfer_record.chain_hash:
            return True
        else:
            prev_hash = token.chain_hash

    if token.chain_hash == transfer_record.chain_hash:
        expected_hash = transfer_record.chain_hash
    else:
        previous = ""
        expected_history_len = max(0, len(token.transfer_history) - 2)
        if token.hop_count == expected_history_len + 1:
            previous = ""
        expected_hash = compute_chain_hash(
            build_tx_payload(
                transfer_record.token_id,
                transfer_record.next_owner_pubkey_hex,
                transfer_record.amount,
                transfer_record.nonce_hex,
            ),
            previous if token.hop_count <= 1 else prev_hash,
        )

    if expected_hash != transfer_record.chain_hash:
        return False
    return ed25519_verify(
        hex_to_pubkey_bytes(transfer_record.prev_owner_pubkey_hex),
        bytes.fromhex(transfer_record.chain_hash),
        bytes.fromhex(transfer_record.signature_hex),
    )


def build_transfer(
    token: Token,
    payer_private_key_bytes: bytes,
    payer_pubkey_hex: str,
    recipient_pubkey_hex: str,
    amount: float,
    policy: PolicyConfig,
    wallet_state: WalletState,
) -> tuple[TransferRecord, Token]:
    del wallet_state
    now = time.time()
    if token.owner_pubkey_hex != payer_pubkey_hex:
        raise ValueError("Wallet does not own token")
    if token.issued_at > now:
        raise ValueError("Invalid token: issued in the future")
    if token.hop_count >= policy.max_offline_hops:
        raise ValueError("Hop limit reached")
    if amount > policy.max_transaction_value_etb:
        raise ValueError("Transaction exceeds offline pocket cash limits")
    if amount > token.denomination:
        raise ValueError("Insufficient token value")
    if now - token.issued_at > policy.token_ttl_seconds:
        raise ValueError("Token expired")

    nonce_hex = generate_nonce_hex()
    payload = build_tx_payload(token.token_id, recipient_pubkey_hex, amount, nonce_hex)
    chain_hash = compute_chain_hash(payload, token.chain_hash)
    signature_hex = sign_transfer(payer_private_key_bytes, chain_hash)
    record = TransferRecord(
        token_id=token.token_id,
        prev_owner_pubkey_hex=payer_pubkey_hex,
        next_owner_pubkey_hex=recipient_pubkey_hex,
        amount=amount,
        nonce_hex=nonce_hex,
        chain_hash=chain_hash,
        signature_hex=signature_hex,
        timestamp=now,
    )
    updated = replace(
        token,
        owner_pubkey_hex=recipient_pubkey_hex,
        hop_count=token.hop_count + 1,
        transfer_history=[*token.transfer_history, recipient_pubkey_hex],
        chain_hash=chain_hash,
    )
    return record, updated
