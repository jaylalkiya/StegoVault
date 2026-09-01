"""Password-based authenticated encryption.

We use AES-256 in GCM mode. GCM is *authenticated* encryption, which means it
does two jobs at once:

    1. Confidentiality - without the password the message is unreadable.
    2. Integrity/tamper-protection - if even one byte of the hidden data is
       altered, decryption FAILS instead of returning garbage. This is the
       "protect it" requirement: nobody can silently modify the secret.

The password never becomes the key directly. Instead we stretch it with
PBKDF2-HMAC-SHA256 using a random salt and many iterations, which makes
brute-force / dictionary attacks far slower.

On-disk / in-image blob layout (all concatenated):

    +--------+----------+--------------------+
    |  salt  |  nonce   |  ciphertext+tag    |
    | 16 B   |  12 B    |  len(msg)+16 B     |
    +--------+----------+--------------------+
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- tunable parameters -----------------------------------------------------
SALT_LEN = 16          # bytes of random salt for the key-derivation function
NONCE_LEN = 12         # AES-GCM standard nonce size
KEY_LEN = 32           # 32 bytes = AES-256
TAG_LEN = 16           # AES-GCM authentication tag appended to the ciphertext
PBKDF2_ITERATIONS = 200_000   # higher = slower to brute force (and to log in)


class DecryptionError(Exception):
    """Raised when the password is wrong or the data has been tampered with."""


def _derive_key(password: str, salt: bytes) -> bytes:
    """Turn a human password into a 32-byte AES key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, password: str) -> bytes:
    """Encrypt ``plaintext`` with ``password`` and return the blob to hide."""
    if not password:
        raise ValueError("A password is required.")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt(blob: bytes, password: str) -> bytes:
    """Reverse :func:`encrypt`.

    Raises :class:`DecryptionError` if the password is wrong or the blob was
    modified (GCM's authentication tag will not verify).
    """
    if len(blob) < SALT_LEN + NONCE_LEN + TAG_LEN:
        raise DecryptionError("Data is too short to be a valid encrypted message.")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:  # cryptography raises InvalidTag
        raise DecryptionError(
            "Wrong password, or the hidden data has been damaged/tampered with."
        ) from exc
