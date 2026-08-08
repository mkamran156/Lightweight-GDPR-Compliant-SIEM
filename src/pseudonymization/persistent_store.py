"""
Persistent pseudonym store implementing the redesigned architecture
described in Section 4.4 (Log Pseudonymization) and Algorithm 1.

Design rationale (from the paper):
    "A persistent pseudonym store, keyed by field type and sensitive
    value, is used to save previously pseudonymized values across the
    full deployment lifetime rather than a single batch. [...] this
    mechanism improves processing time for repeated values and
    guarantees that a given sensitive value always maps to the same
    pseudonym, preserving cross-batch and cross-time correlation for
    attack tracking."

This is a performance cache, not a security boundary: because hashing
is deterministic (MD5 with a static per-field salt), the same value
will always hash to the same pseudonym whether or not it is cached.
The store's purpose is purely to avoid recomputing the hash for values
that repeat across batches (Algorithm 1, lines 9-14).

Contrast with the ORIGINAL (superseded) implementation, which cleared
this cache after every batch -- causing the same value to receive a
DIFFERENT pseudonym in different batches, breaking cross-batch
correlation. That defect is what this persistent design fixes.
"""

from __future__ import annotations

from typing import Optional, Protocol


class PseudonymStoreBackend(Protocol):
    """Storage backend interface. Swap for Redis or Elasticsearch in production."""

    def get(self, key: str) -> Optional[str]: ...
    def set(self, key: str, value: str) -> None: ...


class InMemoryBackend:
    """
    Development/testing backend. Not persistent across process restarts.

    For production, use RedisBackend (below) or an equivalent durable
    key-value store, so the store survives restarts and is shared across
    multiple SIEM server instances if horizontally scaled.
    """

    def __init__(self):
        self._data: dict[str, str] = {}

    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value


class RedisBackend:
    """
    Production backend using Redis, as suggested in Section 4.4:
    "the pseudonym cache is implemented as a persistent key-value store
    (e.g., Redis, or a dedicated Elasticsearch index) rather than being
    cleared after each batch."

    Requires the `redis` package: pip install redis
    """

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        import redis  # deferred import so InMemoryBackend has no hard dependency

        self._client = redis.Redis(host=host, port=port, db=db, decode_responses=True)

    def get(self, key: str) -> Optional[str]:
        return self._client.get(key)

    def set(self, key: str, value: str) -> None:
        # No TTL: entries must persist for the full deployment lifetime.
        self._client.set(key, value)


class PersistentPseudonymStore:
    """
    Value -> pseudonym lookup, keyed by (field_type, sensitive_value).

    Implements the store used in Algorithm 1, lines 9-14:
        pseudonym store key <- (sensitive_field, sensitive_field_value)
        if pseudonym store key not in pseudonym store:
            pseudonymized_value <- MD5(sensitive_field_value, salt[field])
            pseudonym store[key] <- pseudonymized_value   # persisted
        else:
            pseudonymized_value <- pseudonym store[key]
    """

    def __init__(self, backend: PseudonymStoreBackend):
        self._backend = backend

    @staticmethod
    def _make_key(field: str, value: str) -> str:
        return f"{field}:{value}"

    def get(self, field: str, value: str) -> Optional[str]:
        """Return the cached pseudonym for (field, value), or None if not yet computed."""
        return self._backend.get(self._make_key(field, value))

    def put(self, field: str, value: str, pseudonym: str) -> None:
        """Store a newly computed pseudonym. Never cleared per batch."""
        self._backend.set(self._make_key(field, value), pseudonym)
