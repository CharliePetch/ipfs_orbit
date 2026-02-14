import logging

import nacl.public
from nacl.utils import random as nacl_random
from nacl.secret import SecretBox
from base64 import b64decode

logger = logging.getLogger(__name__)


def create_symmetric_key() -> bytes:
    """
    Create a 32-byte symmetric key for encrypting a post.
    """
    return nacl_random(SecretBox.KEY_SIZE)


def encrypt_key_for_follower(sym_key: bytes, follower_public_key_hex: str) -> str | None:
    """
    Encrypt sym_key for a follower using their Curve25519 public key.
    Returns encrypted hex string OR None if invalid key.
    """
    key_hex = follower_public_key_hex.strip().lower()

    # Must be 32 bytes → 64 hex chars
    if len(key_hex) != 64:
        logger.warning(f"Skipping follower (invalid public key length): {key_hex}")
        return None

    try:
        pub_bytes = bytes.fromhex(key_hex)
    except Exception:
        logger.warning(f"Skipping follower (non-hex public key): {key_hex}")
        return None

    try:
        pub = nacl.public.PublicKey(pub_bytes)
    except Exception:
        logger.warning(f"Skipping follower (invalid Curve25519 key): {key_hex}")
        return None

    sealed = nacl.public.SealedBox(pub).encrypt(sym_key)
    return sealed.hex()


# -------------------------------------------------------
#  🔹 LEGACY (base64) envelope decryption
#     (safe to keep for backward compat)
# -------------------------------------------------------
def decrypt_envelope(envelope_b64: str, private_key: nacl.public.PrivateKey) -> bytes:
    """
    Decrypt a base64-encoded envelope (LEGACY FORMAT ONLY).

    envelope_b64: base64-encoded envelope
    Returns: raw symmetric key (bytes)
    """
    encrypted = b64decode(envelope_b64)
    box = nacl.public.SealedBox(private_key)
    return box.decrypt(encrypted)


# -------------------------------------------------------
#  🔹 CURRENT (hex) envelope decryption
#     (used for manifests + rewrap)
# -------------------------------------------------------
def open_envelope(private_key: nacl.public.PrivateKey, envelope_hex: str) -> bytes | None:
    """
    Decrypt a sealed-box envelope (hex → bytes).
    Returns decrypted sym_key or None.
    """
    try:
        encrypted = bytes.fromhex(envelope_hex)
        box = nacl.public.SealedBox(private_key)
        return box.decrypt(encrypted)
    except Exception as e:
        logger.error(f"Envelope decrypt failed: {e}")
        return None
