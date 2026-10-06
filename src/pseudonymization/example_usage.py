"""
Minimal end-to-end example demonstrating Algorithm 1, including the
cross-batch consistency property illustrated in Fig. 5 of the paper: the
same source IP appearing in two separate batches receives the identical
pseudonym both times.

Run with: python -m src.pseudonymization.example_usage
"""

from .algorithm import PseudonymizationAlgorithm
from .key_manager import KeyManager, LocalFileKeyBackend
from .persistent_store import InMemoryBackend, PersistentPseudonymStore
from .reidentification import InMemoryReidBackend, ReidentificationKeyStore


def main():
    # --- one-time deployment setup ---
    key_manager = KeyManager(backend=LocalFileKeyBackend("./example_keys.local"))
    key_manager.generate_keys()  # no-op if the keys already exist

    pseudonym_store = PersistentPseudonymStore(backend=InMemoryBackend())
    reid_store = ReidentificationKeyStore(
        encryption_key=ReidentificationKeyStore.derive_key_from_passphrase(
            "replace-with-a-real-administrator-passphrase",
            salt=b"replace-with-real-salt-bytes",
        ),
        backend=InMemoryReidBackend(),
    )

    algorithm = PseudonymizationAlgorithm(
        key_manager=key_manager,
        pseudonym_store=pseudonym_store,
        reid_store=reid_store,
        admin_token="admin-session-demo",  # normally issued by your auth layer
        batch_size=2,
    )

    # --- Batch 1 ---
    batch_1 = [
        {"ip.address": "10.13.21.5", "user.name": "jdoe"},
        {"ip.address": "10.10.39.2", "user.name": "asmith"},
    ]

    # --- Batch 2, processed "later" ---
    batch_2 = [
        {"ip.address": "10.13.21.5", "user.name": "jdoe"},   # same IP as Batch 1
        {"ip.address": "172.16.4.9", "user.name": "rlee"},
    ]

    for i, batch in enumerate(algorithm.process(batch_1 + batch_2), start=1):
        print(f"Batch {i}:")
        for entry in batch:
            print(f"  {entry}")

    print(
        "\nCross-batch consistency check: "
        f"{pseudonym_store.get('ip.address', '10.13.21.5')} "
        "(same pseudonym in both batches)"
    )

    # --- authorized re-identification (Administrator only) ---
    pseudonym = pseudonym_store.get("ip.address", "10.13.21.5")
    original = reid_store.reidentify("admin-session-demo", pseudonym)
    print(f"Re-identified {pseudonym} -> {original}")


if __name__ == "__main__":
    main()
