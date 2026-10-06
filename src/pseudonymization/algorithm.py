"""
Algorithm 1: Log Pseudonymization (Low Resource Constraint)

Direct implementation of Algorithm 1 as presented in Section 4.4 of the
paper. Reproduced here for reference:

    Input:  Log data from Wazuh Agents or other SIEM endpoints.
    Output: Pseudonymized logs with minimized resource usage.

     1: batch size <- 1000 logs (Configurable)
     2: buffer <- allocate minimal memory for batch processing
     3: sensitive_fields_list <- {user.name, user.email, ip.address}
     4: while logs to process do
     5:     batch <- get next batch(logs, batch size)
     6:     for each log entry in batch do
     7:         for each sensitive field in sensitive fields list do
     8:             if sensitive field exists in log entry then
     9:                 pseudonym store key <- (sensitive field, sensitive field value)
    10:                 if pseudonym store key not in pseudonym store then
    11:                     pseudonymized value <- HMAC-SHA-256 (key[sensitive field],
                                                                sensitive field value)
    12:                     pseudonym store[pseudonym store key] <- pseudonymized value
                            // persisted, not batch-scoped
    13:                 else
    14:                     pseudonymized value <- pseudonym store[pseudonym store key]
    15:                 end if
    16:                 log entry[sensitive field] <- pseudonymized value
    17:             end if
    18:         end for
    19:     end for
    20:     store logs(batch)
    21:     clear(buffer)  // per-batch memory only
    22:     // pseudonym store persists across batches and system lifetime, not cleared

On the choice of primitive (Section 6.1 of the paper):

    The scheme uses HMAC-SHA-256 keyed with a per-field secret. Security
    against re-identification rests on the secrecy of that key, not on
    the collision resistance of the hash, so a keyed construction is the
    natural choice and is in line with the EDPB Guidelines on
    Pseudonymisation. SHA-256 maps to hardware-accelerated instructions
    on modern server CPUs, so the primitive is inexpensive.

    HMAC is used rather than hash(key || value) deliberately: the naive
    prefix construction is vulnerable to length extension against
    Merkle-Damgard hashes such as SHA-256. HMAC is not.

A note on where determinism comes from:

    The persistent store is a performance cache, not the source of
    pseudonym stability. HMAC with a static per-field key is already
    deterministic, so the same value yields the same pseudonym whether
    or not it is cached. The store exists to avoid recomputing the HMAC
    for values that repeat across batches.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Iterable, Iterator, List, Optional

from .key_manager import SENSITIVE_FIELDS, KeyManager
from .persistent_store import PersistentPseudonymStore
from .reidentification import ReidentificationKeyStore

LogEntry = Dict[str, str]


class PseudonymizationAlgorithm:
    """Batch-processing log pseudonymization engine implementing Algorithm 1."""

    def __init__(
        self,
        key_manager: KeyManager,
        pseudonym_store: PersistentPseudonymStore,
        reid_store: Optional[ReidentificationKeyStore] = None,
        admin_token: Optional[str] = None,
        batch_size: int = 1000,
        sensitive_fields: Iterable[str] = SENSITIVE_FIELDS,
    ):
        self._keys = key_manager
        self._store = pseudonym_store
        self._reid_store = reid_store
        self._admin_token = admin_token
        self.batch_size = batch_size
        self.sensitive_fields = tuple(sensitive_fields)

    def process(self, logs: Iterable[LogEntry]) -> Iterator[List[LogEntry]]:
        """
        Process a stream of log entries in fixed-size batches
        (Algorithm 1, lines 4 to 22). Yields one pseudonymized batch at a time.
        """
        buffer: List[LogEntry] = []
        for entry in logs:
            buffer.append(entry)
            if len(buffer) >= self.batch_size:
                yield self._process_batch(buffer)
                buffer = []  # line 21: clear the per-batch buffer only

        if buffer:  # final partial batch
            yield self._process_batch(buffer)

    def _process_batch(self, batch: List[LogEntry]) -> List[LogEntry]:
        """Pseudonymize a single batch (Algorithm 1, lines 6 to 19)."""
        for entry in batch:
            for field in self.sensitive_fields:
                if field not in entry:
                    continue
                entry[field] = self._pseudonymize_value(field, entry[field])
        return batch

    def _pseudonymize_value(self, field: str, value: str) -> str:
        """
        Look up or compute the pseudonym for one sensitive value
        (Algorithm 1, lines 9 to 16).

        The store is consulted first so that a repeated value costs a
        lookup rather than an HMAC computation. A cache miss computes the
        HMAC and records it. Both paths return the same pseudonym for the
        same input, because the key is static.
        """
        cached = self._store.get(field, value)
        if cached is not None:
            return cached

        pseudonym = self._hash(value, self._keys.get_key(field))
        self._store.put(field, value, pseudonym)

        if self._reid_store is not None:
            self._reid_store.record(self._admin_token, field, value, pseudonym)

        return pseudonym

    @staticmethod
    def _hash(value: str, key: bytes) -> str:
        """
        HMAC-SHA-256(key[field], value), as specified in Algorithm 1, line 11.

        Returns the hex digest. See the module docstring and Section 6.1
        of the paper for why a keyed MAC is used rather than a salted hash.
        """
        return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
