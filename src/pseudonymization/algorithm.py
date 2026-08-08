"""
Algorithm 1: Log Pseudonymization (Low Resource Constraint)

Direct implementation of Algorithm 1 as presented in Section 4.4 of the
paper. Reproduced here for reference:

    Input: Log data from Wazuh Agents or other SIEM endpoints
    Output: Pseudonymized logs with minimized resource usage

    1:  batch_size <- 1000 logs (configurable)
    2:  allocate minimal memory for batch processing
    3:  sensitive_fields_list <- {user.name, user.email, ip.address}
        buffer <- []
    4:  while logs to process do
    5:      batch <- get_next_batch(logs, batch_size)
    6:      for each log entry in batch do
    7:          for each sensitive field in sensitive_fields_list do
    8:              if sensitive field exists in log entry then
    9:                  pseudonym_store_key <- (sensitive_field, value)
    10:                 if pseudonym_store_key not in pseudonym_store then
    11:                     pseudonymized_value <- MD5(value, salt[field])
    12:                     pseudonym_store[key] <- pseudonymized_value
                                # persisted, not batch-scoped
    13:                 else
    14:                     pseudonymized_value <- pseudonym_store[key]
    15:                 end if
    16:                 log_entry[field] <- pseudonymized_value
    17:             end if
    18:         end for
    19:     end for
    20:     store_logs(batch)
    21:     clear(buffer)  # per-batch memory only
    22:     # pseudonym store persists across batches and system lifetime
    23: end while

Security note (Section 6.1, "On the Use of MD5 for Pseudonymization"):
MD5 is used here for its low computational overhead, consistent with
the resource-constrained design goal. Its use is contingent on salt
secrecy (Section 4.3, Threat Model) rather than on MD5's own collision
resistance. Migrating to SHA-256 or BLAKE3 while retaining the same
salting and persistent-store design is the recommended next iteration.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, Iterator, List, Optional

from .persistent_store import PersistentPseudonymStore
from .reidentification import ReidentificationKeyStore
from .salt_manager import SENSITIVE_FIELDS, SaltManager

LogEntry = Dict[str, str]


class PseudonymizationAlgorithm:
    """
    Batch-processing log pseudonymization engine implementing Algorithm 1.
    """

    def __init__(
        self,
        salt_manager: SaltManager,
        pseudonym_store: PersistentPseudonymStore,
        reid_store: Optional[ReidentificationKeyStore] = None,
        admin_token: Optional[str] = None,
        batch_size: int = 1000,
        sensitive_fields: Iterable[str] = SENSITIVE_FIELDS,
    ):
        self._salts = salt_manager
        self._store = pseudonym_store
        self._reid_store = reid_store
        self._admin_token = admin_token
        self.batch_size = batch_size
        self.sensitive_fields = tuple(sensitive_fields)

    def process(self, logs: Iterable[LogEntry]) -> Iterator[List[LogEntry]]:
        """
        Process an arbitrary stream of log entries in fixed-size batches
        (Algorithm 1, lines 4-23). Yields one pseudonymized batch at a time.
        """
        buffer: List[LogEntry] = []
        for entry in logs:
            buffer.append(entry)
            if len(buffer) >= self.batch_size:
                yield self._process_batch(buffer)
                buffer = []  # line 21: clear per-batch buffer only

        if buffer:  # final partial batch
            yield self._process_batch(buffer)

    def _process_batch(self, batch: List[LogEntry]) -> List[LogEntry]:
        """Pseudonymize a single batch (Algorithm 1, lines 6-19)."""
        for entry in batch:
            for field in self.sensitive_fields:
                if field not in entry:
                    continue
                value = entry[field]
                entry[field] = self._pseudonymize_value(field, value)
        return batch

    def _pseudonymize_value(self, field: str, value: str) -> str:
        """
        Look up or compute the pseudonym for a single sensitive value
        (Algorithm 1, lines 9-16). This is where cross-batch consistency
        is enforced: the persistent store is checked first, and only a
        cache miss triggers a new hash computation.
        """
        cached = self._store.get(field, value)
        if cached is not None:
            return cached

        salt = self._salts.get_salt(field)
        pseudonym = self._hash(value, salt)
        self._store.put(field, value, pseudonym)

        if self._reid_store is not None:
            self._reid_store.record(self._admin_token, field, value, pseudonym)

        return pseudonym

    @staticmethod
    def _hash(value: str, salt: str) -> str:
        """
        MD5(value, salt) as specified in Algorithm 1, line 11.

        See the module docstring and Section 6.1 of the paper for the
        security rationale and the planned SHA-256/BLAKE3 migration.
        """
        return hashlib.md5(f"{salt}{value}".encode("utf-8")).hexdigest()
