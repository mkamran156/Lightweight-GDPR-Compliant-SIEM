"""
Tests for the properties the paper claims of Algorithm 1.

Run from the repository root:

    pip install -r src/pseudonymization/requirements.txt --break-system-packages
    python -m pytest tests/ -v

Each test names the section or claim of the paper it checks, so that a
reader can go from a claim in the text to the test that exercises it.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.pseudonymization.algorithm import PseudonymizationAlgorithm
from src.pseudonymization.key_manager import KeyManager, KeyBackend, SENSITIVE_FIELDS
from src.pseudonymization.persistent_store import (
    InMemoryBackend,
    PersistentPseudonymStore,
)
from src.pseudonymization.reidentification import (
    InMemoryReidBackend,
    ReidentificationKeyStore,
)


class DictKeyBackend(KeyBackend):
    """In-memory key backend, so tests never touch the filesystem."""

    def __init__(self):
        self._keys = {}

    def load(self):
        return dict(self._keys)

    def save(self, keys):
        self._keys = dict(keys)


@pytest.fixture
def algorithm():
    km = KeyManager(backend=DictKeyBackend())
    km.generate_keys()
    return PseudonymizationAlgorithm(
        key_manager=km,
        pseudonym_store=PersistentPseudonymStore(backend=InMemoryBackend()),
        batch_size=2,
    )


def test_pseudonym_is_a_sha256_hex_digest(algorithm):
    """Section 6.1: the primitive is HMAC-SHA-256, so 64 hex characters."""
    out = next(algorithm.process([{"ip.address": "10.13.21.5"}]))
    pseudonym = out[0]["ip.address"]
    assert len(pseudonym) == 64
    assert all(c in "0123456789abcdef" for c in pseudonym)


def test_same_value_same_pseudonym_within_a_batch(algorithm):
    """Section 4.4: the scheme is deterministic."""
    out = next(
        algorithm.process(
            [{"ip.address": "10.13.21.5"}, {"ip.address": "10.13.21.5"}]
        )
    )
    assert out[0]["ip.address"] == out[1]["ip.address"]


def test_same_value_same_pseudonym_across_batches(algorithm):
    """
    Section 4.4 and Fig. 5: cross-batch consistency. batch_size is 2, so
    the two entries below are pseudonymized in separate batches.
    """
    batches = list(
        algorithm.process(
            [
                {"ip.address": "10.13.21.5"},
                {"ip.address": "10.10.39.2"},
                {"ip.address": "10.13.21.5"},
                {"ip.address": "172.16.4.9"},
            ]
        )
    )
    assert len(batches) == 2
    assert batches[0][0]["ip.address"] == batches[1][0]["ip.address"]


def test_consistency_comes_from_the_key_not_the_store():
    """
    Section 4.4. The paper's Fig. 5 discussion can be read as saying the
    persistent store is what keeps pseudonyms stable. It is not: HMAC
    under a static key is already deterministic, and the store only
    avoids recomputation. Two algorithm instances that share a key but
    have SEPARATE, EMPTY stores must still agree.
    """
    backend = DictKeyBackend()
    km = KeyManager(backend=backend)
    km.generate_keys()

    def fresh():
        return PseudonymizationAlgorithm(
            key_manager=KeyManager(backend=backend),
            pseudonym_store=PersistentPseudonymStore(backend=InMemoryBackend()),
            batch_size=10,
        )

    a = next(fresh().process([{"ip.address": "10.13.21.5"}]))[0]["ip.address"]
    b = next(fresh().process([{"ip.address": "10.13.21.5"}]))[0]["ip.address"]
    assert a == b


def test_different_fields_use_different_keys(algorithm):
    """
    Section 4.2: distinct keys per field type, so that compromise of one
    field's key does not expose the values behind another field's
    pseudonyms. The same string in two fields must not collide.
    """
    out = next(
        algorithm.process([{"user.name": "10.13.21.5", "ip.address": "10.13.21.5"}])
    )
    assert out[0]["user.name"] != out[0]["ip.address"]


def test_batch_size_does_not_change_the_output():
    """
    Section 4.4: batching is a resource control, not part of the
    transform. The same input must pseudonymize identically at any batch
    size.
    """
    backend = DictKeyBackend()
    KeyManager(backend=backend).generate_keys()
    logs = [{"ip.address": f"10.0.0.{i}"} for i in range(7)]

    def run(batch_size):
        alg = PseudonymizationAlgorithm(
            key_manager=KeyManager(backend=backend),
            pseudonym_store=PersistentPseudonymStore(backend=InMemoryBackend()),
            batch_size=batch_size,
        )
        out = []
        for b in alg.process([dict(e) for e in logs]):
            out.extend(e["ip.address"] for e in b)
        return out

    assert run(1) == run(3) == run(100)


def test_non_sensitive_fields_are_left_alone(algorithm):
    """Only the fields in SENSITIVE_FIELDS are transformed."""
    out = next(
        algorithm.process([{"ip.address": "10.13.21.5", "event.action": "login"}])
    )
    assert out[0]["event.action"] == "login"


def test_reidentification_requires_an_admin_token():
    """
    Section 4.2: re-identification is restricted to the Administrator
    role. An empty token must be refused rather than silently allowed.
    """
    store = ReidentificationKeyStore(
        encryption_key=ReidentificationKeyStore.derive_key_from_passphrase(
            "test-passphrase", salt=b"test-salt-bytes"
        ),
        backend=InMemoryReidBackend(),
    )
    with pytest.raises(PermissionError):
        store.record("", "ip.address", "10.13.21.5", "deadbeef")
    with pytest.raises(PermissionError):
        store.reidentify("", "deadbeef")


def test_authorized_reidentification_round_trips():
    """Section 4.2: the Administrator can recover the original value."""
    store = ReidentificationKeyStore(
        encryption_key=ReidentificationKeyStore.derive_key_from_passphrase(
            "test-passphrase", salt=b"test-salt-bytes"
        ),
        backend=InMemoryReidBackend(),
    )
    store.record("admin", "ip.address", "10.13.21.5", "deadbeef")
    assert store.reidentify("admin", "deadbeef") == "10.13.21.5"


def test_every_sensitive_field_has_a_key():
    """Algorithm 1, line 3: all three field types must be provisioned."""
    km = KeyManager(backend=DictKeyBackend())
    km.generate_keys()
    for field in SENSITIVE_FIELDS:
        assert len(km.get_key(field)) == 32  # 256-bit keys, per RFC 2104
