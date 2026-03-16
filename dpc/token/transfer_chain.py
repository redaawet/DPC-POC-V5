from dpc.crypto.signatures import sign_payload, verify_signature
from dpc.token.token_model import Token


def _transfer_payload(token_id: str, from_pk: str, to_pk: str, index: int) -> bytes:
    return f"{token_id}|{from_pk}|{to_pk}|{index}".encode()


def append_transfer(token: Token, sender_private_key: bytes, receiver_public_key_hex: str) -> None:
    index = len(token.transfer_chain)
    from_pk = token.owner_pk
    payload = _transfer_payload(token.token_id, from_pk, receiver_public_key_hex, index)
    signature = sign_payload(sender_private_key, payload)
    token.transfer_chain.append(
        {
            "from_pk": from_pk,
            "to_pk": receiver_public_key_hex,
            "signature": signature,
            "index": index,
        }
    )
    token.owner_pk = receiver_public_key_hex


def validate_transfer_chain(token: Token) -> bool:
    current_owner = token.transfer_chain[0]["from_pk"] if token.transfer_chain else token.owner_pk

    for step in token.transfer_chain:
        if step["from_pk"] != current_owner:
            return False
        payload = _transfer_payload(token.token_id, step["from_pk"], step["to_pk"], step["index"])
        signer_key = bytes.fromhex(step["from_pk"])
        if not verify_signature(signer_key, payload, step["signature"]):
            return False
        current_owner = step["to_pk"]

    return current_owner == token.owner_pk
