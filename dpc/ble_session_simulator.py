"""BLE proximity-session simulator for encrypted token exchange."""

from __future__ import annotations

import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from constants import JSON_SEPARATORS
from crypto_utils import DPCKeyPair, derive_session_key
from exceptions import SessionDecryptionError
from token_model import Token, TransferRecord


class BLESession:
    """Simulated BLE payment session using X25519 and ChaCha20-Poly1305.

    Parameters: payer and payee key pairs.
    Returns: session object able to handshake, encrypt, and decrypt token payloads.
    Raises: no custom exceptions at construction.
    """

    def __init__(self, payer_keypair: DPCKeyPair, payee_keypair: DPCKeyPair) -> None:
        """Create a BLE session simulator.

        Parameters: payer and payee DPC key pairs.
        Returns: None.
        Raises: no custom exceptions.
        """
        self.payer_keypair = payer_keypair
        self.payee_keypair = payee_keypair
        self._session_key: bytes | None = None

    def handshake(self) -> tuple[bytes, bytes]:
        """Perform an ephemeral X25519 handshake.

        Parameters: none.
        Returns: payer and payee session keys.
        Raises: AssertionError if ECDH derivation disagrees.
        """
        payer_eph_priv = X25519PrivateKey.generate()
        payee_eph_priv = X25519PrivateKey.generate()
        payer_nonce = secrets.token_bytes(16)
        payee_nonce = secrets.token_bytes(16)
        session_nonce = payer_nonce + payee_nonce
        payer_session_key = derive_session_key(
            payer_eph_priv,
            payee_eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            session_nonce,
        )
        payee_session_key = derive_session_key(
            payee_eph_priv,
            payer_eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            session_nonce,
        )
        assert payer_session_key == payee_session_key
        self._session_key = payer_session_key
        return payer_session_key, payee_session_key

    def encrypt_payload(self, token: Token, chain: list[TransferRecord]) -> bytes:
        """Encrypt a token and chain payload.

        Parameters: token and transfer chain.
        Returns: nonce-prefixed ciphertext bytes.
        Raises: SessionDecryptionError when handshake has not run.
        """
        if self._session_key is None:
            raise SessionDecryptionError("Session key not established")
        payload = {
            "token": json.loads(token.to_json()),
            "chain": [record.to_dict() for record in chain],
        }
        plaintext = json.dumps(payload, sort_keys=True, separators=JSON_SEPARATORS).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ciphertext = ChaCha20Poly1305(self._session_key).encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_payload(self, encrypted_bytes: bytes) -> tuple[Token, list[TransferRecord]]:
        """Decrypt a nonce-prefixed BLE token payload.

        Parameters: encrypted_bytes produced by encrypt_payload.
        Returns: token and transfer chain.
        Raises: SessionDecryptionError on missing session key or authentication failure.
        """
        if self._session_key is None:
            raise SessionDecryptionError("Session key not established")
        if len(encrypted_bytes) < 13:
            raise SessionDecryptionError("Encrypted payload is too short")
        nonce, ciphertext = encrypted_bytes[:12], encrypted_bytes[12:]
        try:
            plaintext = ChaCha20Poly1305(self._session_key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise SessionDecryptionError("BLE payload authentication failed") from exc
        payload = json.loads(plaintext.decode("utf-8"))
        return Token(**payload["token"]), [TransferRecord.from_dict(item) for item in payload["chain"]]

    def simulate_transfer(self, token: Token, chain: list[TransferRecord]) -> tuple[Token, list[TransferRecord]]:
        """Run handshake, encryption, and decryption for a simulated BLE transfer.

        Parameters: token and transfer chain.
        Returns: decrypted token and chain.
        Raises: SessionDecryptionError if encryption or decryption fails.
        """
        self.handshake()
        received_token, received_chain = self.decrypt_payload(self.encrypt_payload(token, chain))
        assert received_token.token_id == token.token_id
        return received_token, received_chain
