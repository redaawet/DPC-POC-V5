"""Cryptographic primitives used by the Digital Pocket Cash PoC."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from exceptions import SignatureVerificationError


@dataclass
class DPCKeyPair:
    """Persistent Ed25519 wallet identity key pair.

    Parameters: private/public Ed25519 key objects stored in memory.
    Returns: a key-pair object for signing and public identity export.
    Raises: cryptography backend exceptions if key generation fails.
    """

    _private_key: Ed25519PrivateKey
    _public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "DPCKeyPair":
        """Generate a new wallet identity key pair.

        Parameters: none.
        Returns: DPCKeyPair containing Ed25519 private and public keys.
        Raises: cryptography backend exceptions if entropy or key generation fails.
        """
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key, private_key.public_key())

    def public_key_hex(self) -> str:
        """Return the wallet public identity key.

        Parameters: none.
        Returns: 64-character hex-encoded raw Ed25519 public key.
        Raises: cryptography serialization exceptions if serialization fails.
        """
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def private_key_bytes(self) -> bytes:
        """Return raw private key bytes for local signing helpers.

        Parameters: none.
        Returns: 32 raw Ed25519 private key bytes.
        Raises: cryptography serialization exceptions if serialization fails.
        """
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the wallet Ed25519 identity.

        Parameters: message bytes to authenticate.
        Returns: raw Ed25519 signature bytes.
        Raises: cryptography backend exceptions if signing fails.
        """
        return self._private_key.sign(message)

    def derive_x25519_private(self) -> X25519PrivateKey:
        """Derive a static X25519 private key from the Ed25519 identity key.

        Parameters: none.
        Returns: X25519PrivateKey derived via HKDF domain separation.
        Raises: cryptography backend exceptions if derivation fails.
        """
        raw_ed_bytes = self.private_key_bytes()
        # Derive X25519 from Ed25519 via HKDF so the same identity key serves both signing and ECDH without key-reuse weaknesses.
        x25519_seed = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"DPC-X25519-Derive-v1").derive(raw_ed_bytes)
        return X25519PrivateKey.from_private_bytes(x25519_seed)


def ed25519_sign(private_key_bytes: bytes, message: bytes) -> str:
    """Sign a message with an Ed25519 private key.

    Parameters: private_key_bytes is the 32-byte raw Ed25519 secret; message is bytes to sign.
    Returns: hex-encoded Ed25519 signature.
    Raises: cryptography backend exceptions if the private key is invalid or signing fails.
    """
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    # Ed25519 signs the chain hash bytes so transfer authenticity is bound to tamper-evident history.
    return private_key.sign(message).hex()


def ed25519_verify(public_key_hex: str, message: bytes, signature_hex: str) -> None:
    """Verify an Ed25519 signature.

    Parameters: public_key_hex is a raw 32-byte public key encoded as hex; message and signature_hex are verified.
    Returns: None when the signature is valid.
    Raises: SignatureVerificationError when the signature or key material is invalid.
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), message)
    except (InvalidSignature, ValueError) as exc:
        raise SignatureVerificationError("Ed25519 signature verification failed") from exc


def derive_session_key(local_x25519_private: X25519PrivateKey, peer_x25519_public_bytes: bytes, session_nonce: bytes) -> bytes:
    """Derive a ChaCha20-Poly1305 session key using X25519 and HKDF-SHA256.

    Parameters: local_x25519_private, peer public X25519 bytes, and a 32-byte two-party nonce.
    Returns: 32-byte symmetric session key.
    Raises: cryptography backend exceptions if peer key parsing or derivation fails.
    """
    peer_pub = X25519PublicKey.from_public_bytes(peer_x25519_public_bytes)
    shared_secret = local_x25519_private.exchange(peer_pub)
    return HKDF(
        algorithm=SHA256(),
        length=32,
        # The payer_nonce + payee_nonce salt makes reused key pairs produce fresh session keys.
        salt=session_nonce,
        info=b"DPC-ChaCha20-Session-v1",
    ).derive(shared_secret)
