"""Configuration management for Learning Battery Market.

Centralizes all configurable parameters with environment variable support
and runtime overrides.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import json


def _env_int(key: str, default: int) -> int:
    """Get integer from environment variable."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    """Get float from environment variable."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    """Get boolean from environment variable."""
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes", "on")


def _env_str(key: str, default: str) -> str:
    """Get string from environment variable."""
    return os.environ.get(key, default)


@dataclass
class ChainConfig:
    """Configuration for blockchain/chain operations."""

    # Nonce management
    nonce_expiry_ms: int = field(default_factory=lambda: _env_int("LB_NONCE_EXPIRY_MS", 24 * 60 * 60 * 1000))  # 24 hours
    min_nonce_length: int = field(default_factory=lambda: _env_int("LB_MIN_NONCE_LENGTH", 32))  # 256 bits hex

    # Timestamp validation
    max_clock_drift_ms: int = field(default_factory=lambda: _env_int("LB_MAX_CLOCK_DRIFT_MS", 5 * 60 * 1000))  # 5 minutes

    # Block limits
    max_block_size_bytes: int = field(default_factory=lambda: _env_int("LB_MAX_BLOCK_SIZE_BYTES", 1 * 1024 * 1024))  # 1MB
    max_txs_per_block: int = field(default_factory=lambda: _env_int("LB_MAX_TXS_PER_BLOCK", 100))


@dataclass
class P2PConfig:
    """Configuration for P2P networking."""

    # Timeouts
    connect_timeout_s: float = field(default_factory=lambda: _env_float("LB_P2P_CONNECT_TIMEOUT_S", 10.0))
    read_timeout_s: float = field(default_factory=lambda: _env_float("LB_P2P_READ_TIMEOUT_S", 30.0))
    handshake_timeout_s: float = field(default_factory=lambda: _env_float("LB_P2P_HANDSHAKE_TIMEOUT_S", 15.0))
    idle_timeout_s: float = field(default_factory=lambda: _env_float("LB_P2P_IDLE_TIMEOUT_S", 300.0))  # 5 minutes

    # Rate limiting
    max_connections_per_ip: int = field(default_factory=lambda: _env_int("LB_P2P_MAX_CONN_PER_IP", 10))
    max_requests_per_minute: int = field(default_factory=lambda: _env_int("LB_P2P_MAX_REQ_PER_MIN", 100))

    # Frame limits
    max_frame_size_bytes: int = field(default_factory=lambda: _env_int("LB_P2P_MAX_FRAME_SIZE", 10 * 1024 * 1024))  # 10MB


@dataclass
class ValidationConfig:
    """Configuration for input validation limits."""

    # String lengths
    max_group_name_length: int = field(default_factory=lambda: _env_int("LB_MAX_GROUP_NAME_LENGTH", 128))
    max_claim_text_length: int = field(default_factory=lambda: _env_int("LB_MAX_CLAIM_TEXT_LENGTH", 65536))  # 64KB
    max_offer_title_length: int = field(default_factory=lambda: _env_int("LB_MAX_OFFER_TITLE_LENGTH", 256))
    max_offer_description_length: int = field(default_factory=lambda: _env_int("LB_MAX_OFFER_DESCRIPTION_LENGTH", 4096))
    max_tag_length: int = field(default_factory=lambda: _env_int("LB_MAX_TAG_LENGTH", 64))
    max_tags_per_item: int = field(default_factory=lambda: _env_int("LB_MAX_TAGS_PER_ITEM", 20))

    # Size limits
    max_package_size_bytes: int = field(default_factory=lambda: _env_int("LB_MAX_PACKAGE_SIZE", 10 * 1024 * 1024))  # 10MB
    max_experience_size_bytes: int = field(default_factory=lambda: _env_int("LB_MAX_EXPERIENCE_SIZE", 1 * 1024 * 1024))  # 1MB

    # Task management limits
    max_task_title_length: int = field(default_factory=lambda: _env_int("LB_MAX_TASK_TITLE_LENGTH", 256))
    max_task_description_length: int = field(default_factory=lambda: _env_int("LB_MAX_TASK_DESC_LENGTH", 4096))
    max_error_message_length: int = field(default_factory=lambda: _env_int("LB_MAX_ERROR_MSG_LENGTH", 1024))

    # Presence/heartbeat
    default_presence_stale_ms: int = field(default_factory=lambda: _env_int("LB_PRESENCE_STALE_MS", 300000))  # 5 minutes


@dataclass
class LoggingConfig:
    """Configuration for logging."""

    level: str = field(default_factory=lambda: _env_str("LB_LOG_LEVEL", "INFO"))
    json_format: bool = field(default_factory=lambda: _env_bool("LB_LOG_JSON", False))
    log_dir: str = field(default_factory=lambda: _env_str("LB_LOG_DIR", ""))
    console_output: bool = field(default_factory=lambda: _env_bool("LB_LOG_CONSOLE", True))


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations.

    Note: Key encryption parameters (Scrypt N/r/p) are intentionally fixed
    in lb/key_encryption.py for security. They are not configurable to prevent
    accidental weakening of key protection.
    """

    # Signature verification
    require_signature_verification: bool = field(default_factory=lambda: _env_bool("LB_REQUIRE_SIG_VERIFY", True))


@dataclass
class SyncConfig:
    """Configuration for sync daemon and auto-sync."""

    # Default sync interval for new subscriptions (5 minutes)
    default_sync_interval_s: int = field(default_factory=lambda: _env_int("LB_SYNC_INTERVAL_S", 300))

    # Minimum allowed sync interval (prevent abuse)
    min_sync_interval_s: int = field(default_factory=lambda: _env_int("LB_SYNC_MIN_INTERVAL_S", 60))

    # Daemon check interval (how often to check subscriptions)
    daemon_check_interval_s: int = field(default_factory=lambda: _env_int("LB_SYNC_CHECK_INTERVAL_S", 10))

    # Auto-start daemon with P2P server
    auto_start_daemon: bool = field(default_factory=lambda: _env_bool("LB_SYNC_AUTO_START", True))

    # Max concurrent sync operations
    max_concurrent_syncs: int = field(default_factory=lambda: _env_int("LB_SYNC_MAX_CONCURRENT", 3))

    # Retry configuration
    retry_delay_s: int = field(default_factory=lambda: _env_int("LB_SYNC_RETRY_DELAY_S", 60))
    max_retries: int = field(default_factory=lambda: _env_int("LB_SYNC_MAX_RETRIES", 3))


@dataclass
class Config:
    """Main configuration container for Learning Battery Market."""

    chain: ChainConfig = field(default_factory=ChainConfig)
    p2p: P2PConfig = field(default_factory=P2PConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    sync: SyncConfig = field(default_factory=SyncConfig)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        from dataclasses import asdict
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        return cls(
            chain=ChainConfig(**d.get("chain", {})) if d.get("chain") else ChainConfig(),
            p2p=P2PConfig(**d.get("p2p", {})) if d.get("p2p") else P2PConfig(),
            validation=ValidationConfig(**d.get("validation", {})) if d.get("validation") else ValidationConfig(),
            logging=LoggingConfig(**d.get("logging", {})) if d.get("logging") else LoggingConfig(),
            crypto=CryptoConfig(**d.get("crypto", {})) if d.get("crypto") else CryptoConfig(),
            sync=SyncConfig(**d.get("sync", {})) if d.get("sync") else SyncConfig(),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Config":
        """Create configuration from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())

    def save(self, path: str) -> None:
        """Save configuration to JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())


# Global configuration instance (singleton pattern)
_global_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance.

    Creates a default configuration if one doesn't exist.
    """
    global _global_config
    if _global_config is None:
        _global_config = Config()
    return _global_config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


def load_config(path: str) -> Config:
    """Load configuration from file and set as global."""
    config = Config.from_file(path)
    set_config(config)
    return config


def reset_config() -> None:
    """Reset global configuration to default."""
    global _global_config
    _global_config = None
