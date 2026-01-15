"""Encrypted key storage for Learning Battery Market.

Implements password-based encryption for key material at rest using:
- Scrypt for key derivation (N=2^17, r=8, p=1 - memory-hard, well-vetted)
- ChaCha20-Poly1305 for authenticated encryption

Security considerations:
- Keys are encrypted individually with unique salts and nonces
- Scrypt parameters tuned for strong security (128MB memory cost)
- File permissions enforced via ensure_mode_600()
- Parameters are intentionally fixed (not configurable) to prevent weakening
"""
from __future__ import annotations

import os
import json
import secrets
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

from .keys import (
    NodeKeys, gen_node_keys,
    dump_sign_priv_raw, dump_enc_priv_raw,
    load_sign_priv_raw, load_enc_priv_raw,
    ensure_mode_600, b64e, b64d
)
from .fs import ensure_dir, atomic_write_bytes, atomic_write_json, read_json
from .logging_config import get_node_logger

logger = get_node_logger()

# Encryption parameters
# Using Scrypt as Argon2id isn't in cryptography by default
# Scrypt is also memory-hard and well-vetted
SCRYPT_N = 2**17  # CPU/memory cost (128MB)
SCRYPT_R = 8      # Block size
SCRYPT_P = 1      # Parallelization
SALT_SIZE = 32    # 256-bit salt
NONCE_SIZE = 12   # ChaCha20-Poly1305 nonce size
KEY_SIZE = 32     # 256-bit key

# Version for future upgrades
ENCRYPTED_KEY_VERSION = 1


class KeyEncryptionError(Exception):
    """Error during key encryption/decryption."""
    pass


@dataclass
class EncryptedKeyFile:
    """Container for encrypted key material."""
    version: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "salt": b64e(self.salt),
            "nonce": b64e(self.nonce),
            "ciphertext": b64e(self.ciphertext),
        }

    @staticmethod
    def from_dict(d: dict) -> "EncryptedKeyFile":
        return EncryptedKeyFile(
            version=int(d["version"]),
            salt=b64d(d["salt"]),
            nonce=b64d(d["nonce"]),
            ciphertext=b64d(d["ciphertext"]),
        )

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "EncryptedKeyFile":
        return EncryptedKeyFile.from_dict(json.loads(data.decode("utf-8")))


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_key_material(key_data: bytes, password: str) -> EncryptedKeyFile:
    """Encrypt key material with password."""
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    derived_key = derive_key(password, salt)
    cipher = ChaCha20Poly1305(derived_key)
    ciphertext = cipher.encrypt(nonce, key_data, associated_data=None)

    return EncryptedKeyFile(
        version=ENCRYPTED_KEY_VERSION,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext
    )


def decrypt_key_material(encrypted: EncryptedKeyFile, password: str) -> bytes:
    """Decrypt key material with password."""
    if encrypted.version != ENCRYPTED_KEY_VERSION:
        raise KeyEncryptionError(f"unsupported key file version: {encrypted.version}")

    derived_key = derive_key(password, encrypted.salt)
    cipher = ChaCha20Poly1305(derived_key)

    try:
        return cipher.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data=None)
    except Exception as e:
        raise KeyEncryptionError("decryption failed - wrong password or corrupted file") from e


def save_encrypted_key(path: Path, key_data: bytes, password: str) -> None:
    """Save encrypted key to file."""
    encrypted = encrypt_key_material(key_data, password)
    atomic_write_bytes(path, encrypted.to_bytes())
    ensure_mode_600(str(path))
    logger.debug(f"Saved encrypted key to {path}")


def load_encrypted_key(path: Path, password: str) -> bytes:
    """Load and decrypt key from file."""
    data = path.read_bytes()
    encrypted = EncryptedKeyFile.from_bytes(data)
    return decrypt_key_material(encrypted, password)


def is_encrypted_key_file(path: Path) -> bool:
    """Check if a key file is encrypted (vs raw bytes)."""
    try:
        data = path.read_bytes()
        # Encrypted files are JSON, raw files are 32 bytes
        if len(data) == 32:
            return False
        # Try to parse as JSON
        d = json.loads(data.decode("utf-8"))
        return "version" in d and "salt" in d and "ciphertext" in d
    except Exception:
        return False


def init_encrypted_keys(data_dir: Path, password: str) -> NodeKeys:
    """Initialize a new node with encrypted keys.

    Args:
        data_dir: Directory to store keys
        password: Password for key encryption

    Returns:
        Generated NodeKeys
    """
    keys_dir = data_dir / "keys"
    ensure_dir(keys_dir)

    keys = gen_node_keys()

    # Save encrypted keys
    sign_path = keys_dir / "signing.key"
    enc_path = keys_dir / "encryption.key"

    save_encrypted_key(sign_path, dump_sign_priv_raw(keys.sign_priv), password)
    save_encrypted_key(enc_path, dump_enc_priv_raw(keys.enc_priv), password)

    logger.info(f"Initialized encrypted keys at {keys_dir}")
    return keys


def load_keys(data_dir: Path, password: Optional[str] = None) -> NodeKeys:
    """Load node keys, handling both encrypted and unencrypted formats.

    Args:
        data_dir: Directory containing keys
        password: Password for encrypted keys (required if encrypted)

    Returns:
        Loaded NodeKeys

    Raises:
        KeyEncryptionError: If password is wrong or missing for encrypted keys
    """
    sign_path = data_dir / "keys" / "signing.key"
    enc_path = data_dir / "keys" / "encryption.key"

    if not sign_path.exists() or not enc_path.exists():
        raise FileNotFoundError("missing key files")

    sign_encrypted = is_encrypted_key_file(sign_path)
    enc_encrypted = is_encrypted_key_file(enc_path)

    if sign_encrypted or enc_encrypted:
        if password is None:
            raise KeyEncryptionError("password required for encrypted keys")

        sign_raw = load_encrypted_key(sign_path, password) if sign_encrypted else sign_path.read_bytes()
        enc_raw = load_encrypted_key(enc_path, password) if enc_encrypted else enc_path.read_bytes()
    else:
        sign_raw = sign_path.read_bytes()
        enc_raw = enc_path.read_bytes()

    sign_priv = load_sign_priv_raw(sign_raw)
    enc_priv = load_enc_priv_raw(enc_raw)

    return NodeKeys(
        sign_priv=sign_priv,
        sign_pub=sign_priv.public_key(),
        enc_priv=enc_priv,
        enc_pub=enc_priv.public_key(),
    )


def encrypt_existing_keys(data_dir: Path, password: str) -> None:
    """Encrypt existing unencrypted keys in place.

    Args:
        data_dir: Directory containing keys
        password: Password for encryption
    """
    sign_path = data_dir / "keys" / "signing.key"
    enc_path = data_dir / "keys" / "encryption.key"

    if not sign_path.exists() or not enc_path.exists():
        raise FileNotFoundError("missing key files")

    if is_encrypted_key_file(sign_path) or is_encrypted_key_file(enc_path):
        raise KeyEncryptionError("keys are already encrypted")

    # Read raw keys
    sign_raw = sign_path.read_bytes()
    enc_raw = enc_path.read_bytes()

    # Encrypt and save
    save_encrypted_key(sign_path, sign_raw, password)
    save_encrypted_key(enc_path, enc_raw, password)

    logger.info(f"Encrypted existing keys at {data_dir / 'keys'}")


def change_key_password(data_dir: Path, old_password: str, new_password: str) -> None:
    """Change password for encrypted keys.

    Args:
        data_dir: Directory containing keys
        old_password: Current password
        new_password: New password
    """
    sign_path = data_dir / "keys" / "signing.key"
    enc_path = data_dir / "keys" / "encryption.key"

    # Decrypt with old password
    sign_raw = load_encrypted_key(sign_path, old_password)
    enc_raw = load_encrypted_key(enc_path, old_password)

    # Re-encrypt with new password
    save_encrypted_key(sign_path, sign_raw, new_password)
    save_encrypted_key(enc_path, enc_raw, new_password)

    logger.info(f"Changed key password for {data_dir / 'keys'}")


def encrypt_wallet_keys(wallet_keys: dict, password: str) -> bytes:
    """Encrypt wallet keys dictionary.

    Args:
        wallet_keys: Dictionary of package_hash -> symmetric_key_b64
        password: Encryption password

    Returns:
        Encrypted bytes
    """
    data = json.dumps(wallet_keys, sort_keys=True).encode("utf-8")
    encrypted = encrypt_key_material(data, password)
    return encrypted.to_bytes()


def decrypt_wallet_keys(data: bytes, password: str) -> dict:
    """Decrypt wallet keys from encrypted bytes.

    Args:
        data: Encrypted wallet keys
        password: Decryption password

    Returns:
        Dictionary of package_hash -> symmetric_key_b64
    """
    encrypted = EncryptedKeyFile.from_bytes(data)
    decrypted = decrypt_key_material(encrypted, password)
    return json.loads(decrypted.decode("utf-8"))
