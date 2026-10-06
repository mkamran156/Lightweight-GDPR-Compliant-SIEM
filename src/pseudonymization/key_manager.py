"""
Per-field key management for the pseudonymization scheme.

Implements the key design described in Section 4.2 of the paper:

    "Distinct static keys are maintained per sensitive-field type (IP
    addresses, usernames, email addresses) rather than a single
    system-wide key, so that compromise of one field's key does not
    allow the original values behind pseudonyms of other field types to
    be recovered."

Keys are static, not regenerated per record or per batch, because the
pseudonymization scheme must be deterministic: the same input value has
to map to the same pseudonym every time, or cross-log correlation for
threat detection breaks (Section 4.3, Threat Model).

This is a secret KEY, not a salt. The distinction matters and is the
subject of Section 6.1 of the paper: security against re-identification
rests on the secrecy of the per-field key, not on the collision
resistance of the hash. A salt is public by convention; these values
are not, and must be protected accordingly.
"""

from __future__ import annotations

import os
import secrets
from typing import Dict

# Fields treated as personal data under the scheme (Algorithm 1, line 3).
# These are the field names used in the paper. Map them to the field names
# your own pipeline emits before deployment; under Elastic Common Schema
# the usual equivalents are source.ip or host.ip, user.name and user.email.
SENSITIVE_FIELDS = ("user.name", "user.email", "ip.address")

# HMAC-SHA-256 keys. RFC 2104 recommends a key at least as long as the
# hash output, so 32 bytes is the floor rather than a nicety.
KEY_BYTES = 32


class KeyManager:
    """Loads and stores one secret key per sensitive-field type."""

    def __init__(self, backend: "KeyBackend"):
        self._backend = backend
        self._keys: Dict[str, bytes] = self._backend.load()

    def get_key(self, field: str) -> bytes:
        """Return the static HMAC key for a given sensitive-field type."""
        if field not in self._keys:
            raise KeyError(
                f"No key provisioned for field '{field}'. "
                f"Run generate_keys() during initial deployment setup."
            )
        return self._keys[field]

    def generate_keys(self, fields=SENSITIVE_FIELDS, overwrite: bool = False) -> None:
        """
        Generate one cryptographically random key per field type.

        Run this exactly once, during initial deployment. Regenerating a
        key after data has been pseudonymized changes every pseudonym for
        that field, which breaks correlation against everything already
        indexed. The paper records the absence of a rotation procedure as
        a limitation (Section 6.2) for this reason.
        """
        for field in fields:
            if field in self._keys and not overwrite:
                continue
            self._keys[field] = secrets.token_bytes(KEY_BYTES)
        self._backend.save(self._keys)


class KeyBackend:
    """Abstract backend interface for key storage."""

    def load(self) -> Dict[str, bytes]:
        raise NotImplementedError

    def save(self, keys: Dict[str, bytes]) -> None:
        raise NotImplementedError


class LocalFileKeyBackend(KeyBackend):
    """
    Development-only backend. Stores keys hex-encoded in a local file.

    NOT suitable for production. The paper's design requires the keys to
    live in a separate, access-controlled index encrypted at rest with
    AES-256 (Section 4.2), readable only by the Administrator role.
    Replace this with an ElasticsearchKeyBackend, a KMS or an HSM before
    deployment.
    """

    def __init__(self, path: str = "./keys.local"):
        self._path = path

    def load(self) -> Dict[str, bytes]:
        if not os.path.exists(self._path):
            return {}
        keys: Dict[str, bytes] = {}
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                field, hexkey = line.split("=", 1)
                keys[field] = bytes.fromhex(hexkey)
        return keys

    def save(self, keys: Dict[str, bytes]) -> None:
        # Create with 0600 from the outset rather than widening then
        # narrowing, so the key material is never briefly world-readable.
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for field, key in keys.items():
                f.write(f"{field}={key.hex()}\n")
