"""
Re-identification key store, as described in Section 4.2 (Component 6):

    "Re-identification keys and per-field pseudonymization salts are
    stored in a dedicated Elasticsearch index, separate from the
    pseudonymized log data, and encrypted at rest using AES-256."
    "The AES-256 encryption key protecting the re-identification key
    store is held by the Administrator role only, is not stored
    alongside the encrypted index, and is rotated annually or
    immediately upon suspected compromise or personnel change."

Because MD5 is a one-way hash, "re-identification" is not achieved by
reversing the hash -- it is achieved by maintaining a SEPARATE,
access-controlled, encrypted table that records the reverse mapping
(pseudonym -> original value) at the time of pseudonymization. This is
distinct from persistent_store.py (the forward value->pseudonym cache
used to avoid recomputation): this module is the sensitive artifact
that actually enables authorized re-identification, and access to it
must be restricted to the Administrator role per the RBAC design
(Section 4.2, Component 7).

Do not connect this store to the same access path as ordinary log
queries. Only expose it through an explicitly Administrator-gated
interface.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.fernet import Fernet  # AES-based authenticated encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class ReidentificationKeyStore:
    """
    Encrypted, access-controlled pseudonym -> original-value mapping.

    Every write requires an `admin_token` to be supplied by the caller;
    this reference implementation does not validate that token itself
    -- it assumes the caller (e.g., the RBAC layer in src/rbac/) has
    already authenticated the request as coming from the Administrator
    role before invoking this store. Wire this up to your real
    authentication/authorization system before deployment.
    """

    def __init__(self, encryption_key: bytes, backend: "ReidStoreBackend"):
        self._fernet = Fernet(encryption_key)
        self._backend = backend

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
        """
        Derive a Fernet-compatible key from an Administrator-held passphrase.

        The resulting key must be held by the Administrator role only and
        never stored alongside the encrypted index (per the paper's design).
        Store `salt` (not secret, but needed for key derivation) separately
        from both the key and the encrypted data.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

    def record(self, admin_token: str, field: str, original_value: str, pseudonym: str) -> None:
        """
        Record a reverse mapping at pseudonymization time.

        Called once per newly-seen (field, value) pair, immediately after
        Algorithm 1 computes a new pseudonym (see algorithm.py).
        """
        self._require_admin(admin_token)
        plaintext = f"{original_value}".encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)
        self._backend.set(pseudonym, ciphertext)

    def reidentify(self, admin_token: str, pseudonym: str) -> Optional[str]:
        """
        Reverse a pseudonym back to its original value.

        Restricted to the Administrator role. All calls to this method
        should themselves be logged to the access-audit index described
        in Section 4.2 ("Access audit logs are themselves stored in a
        separate, append-only Elasticsearch index...").
        """
        self._require_admin(admin_token)
        ciphertext = self._backend.get(pseudonym)
        if ciphertext is None:
            return None
        return self._fernet.decrypt(ciphertext).decode("utf-8")

    @staticmethod
    def _require_admin(admin_token: str) -> None:
        if not admin_token:
            raise PermissionError(
                "Re-identification requires an authenticated Administrator "
                "token. See src/rbac/roles.yaml for role definitions."
            )
        # This guard enforces that a caller identity is present; the RBAC
        # layer (src/rbac/access_control.py) performs the full role check.


class ReidStoreBackend:
    """Abstract backend interface. Bind to an encrypted Elasticsearch index in production."""

    def get(self, pseudonym: str) -> Optional[bytes]:
        raise NotImplementedError

    def set(self, pseudonym: str, ciphertext: bytes) -> None:
        raise NotImplementedError


class InMemoryReidBackend(ReidStoreBackend):
    """Development/testing backend only. Not durable, not access-controlled at rest."""

    def __init__(self):
        self._data: dict[str, bytes] = {}

    def get(self, pseudonym: str) -> Optional[bytes]:
        return self._data.get(pseudonym)

    def set(self, pseudonym: str, ciphertext: bytes) -> None:
        self._data[pseudonym] = ciphertext
