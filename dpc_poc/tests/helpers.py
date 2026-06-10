from __future__ import annotations

from dataclasses import replace

from dpc.models import Token, TransferRecord
from dpc.wallet import Wallet


def mint_direct(issuer: Wallet, owner: Wallet, denomination: float) -> Token:
    token = issuer.issue_token(denomination)
    issuer.state.unspent_tokens.pop(token.token_id, None)
    owned = replace(
        token,
        owner_pubkey_hex=owner.pubkey_hex,
        transfer_history=[issuer.pubkey_hex, owner.pubkey_hex],
    )
    owner.state.unspent_tokens[owned.token_id] = owned
    return owned


def result_line(test_name: str, passed: bool, reason: str) -> bool:
    status = "PASS" if passed else "FAIL"
    print(f"[{test_name}] {status}: {reason}")
    return passed
