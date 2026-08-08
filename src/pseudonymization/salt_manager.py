"""
Per-field salt management for the pseudonymization scheme.

Implements the salt design described in Section 4.2 of the paper:
"Distinct static salts are maintained per sensitive-field type (IP
addresses, usernames, email addresses) rather than a single system-wide
salt, so that compromise of one field's salt does not expose pseudonyms
for other field types."

Salts are static (not regenerated per record or per batch) because the
pseudonymization scheme must be deterministic: the same input value has
to map to the same pseudonym every time, or cross-log correlation for
threat detection breaks (see Section 4.3, Threat Model).
"""

from __future__ import annotations

import os
import secrets
from typing import Dict


# Fields treated as sensitive/personal data under the scheme (Section 4.4).
SENSITIVE_FIELDS = ("user.name", "user.email", "host.ip")


class SaltManager:
    """
    Loads and stores one salt per sensitive-field type.

    In production, salts must be persisted somewhere separate from the
    pseudonymized log data (Section 4.2: "stored in a dedicated
    Elasticsearch index, separate from the pseudonymized log data, and
    encrypted at rest using AES-256"). This reference implementation
    supports a pluggable backend; the default is a local encrypted file
    for development/testing only.
    """

    def __init__(self, backend: "SaltBackend"):
        self._backend = backend
        self._salts: Dict[str, str] = self._backend.load()

    def get_salt(self, field: str) -> str:
        """Return the static salt for a given sensitive field type."""
        if field not in self._salts:
            raise KeyError(
                f"No salt provisioned for field '{field}'. "
                f"Run generate_salts() during initial deployment setup."
            )
        return self._salts[field]

    def generate_salts(self, fields=SENSITIVE_FIELDS, overwrite: bool = False) -> None:
        """
        Generate one cryptographically random salt per field type.

        This should be run exactly once during initial deployment.
        Regenerating salts after data has been pseudonymized breaks
        cross-batch consistency for all previously processed values.
        """
        for field in fields:
            if field in self._salts and not overwrite:
                continue
            # 256 bits of entropy per salt.
            self._salts[field] = secrets.token_hex(32)
        self._backend.save(self._salts)


class SaltBackend:
    """Abstract backend interface for salt storage."""

    def load(self) -> Dict[str, str]:
        raise NotImplementedError

    def save(self, salts: Dict[str, str]) -> None:
        raise NotImplementedError


class LocalFileSaltBackend(SaltBackend):
    """
    Development-only backend. Stores salts in a local file.

    NOT suitable for production: the paper's design requires salts to be
    stored in a separate, access-controlled, AES-256-encrypted index
    (Section 4.2), with access restricted to the Administrator role
    (Section 4.2, RBAC). Replace this with an ElasticsearchSaltBackend
    or equivalent before deployment.
    """

    def __init__(self, path: str = "./salts.local"):
        self._path = path

    def load(self) -> Dict[str, str]:
        if not os.path.exists(self._path):
            return {}
        salts: Dict[str, str] = {}
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                field, salt = line.strip().split("=", 1)
                salts[field] = salt
        return salts

    def save(self, salts: Dict[str, str]) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            for field, salt in salts.items():
                f.write(f"{field}={salt}\n")
        os.chmod(self._path, 0o600)
