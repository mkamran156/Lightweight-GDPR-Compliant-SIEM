"""
Minimal end-to-end example demonstrating the algorithm, including the
cross-batch consistency property illustrated in Fig. 5 of the paper:
the same source IP appearing in two separate batches receives the
identical pseudonym both times.

Run with: python -m src.pseudonymization.example_usage
"""

from .algorithm import PseudonymizationAlgorithm
from .persistent_store import InMemoryBackend, PersistentPseudonymStore
from .reidentification import InMemoryReidBackend, ReidentificationKeyStore
from .salt_manager import LocalFileSaltBackend, SaltManager


def main():
    # --- one-time deployment setup ---
    salt_manager = SaltManager(backend=LocalFileSaltBackend("./example_salts.local"))
    salt_manager.generate_salts()  # no-op if salts already exist

    pseudonym_store = PersistentPseudonymStore(backend=InMemoryBackend())
    reid_store = ReidentificationKeyStore(
        encryption_key=ReidentificationKeyStore.derive_key_from_passphrase(
            "replace-with-a-real-administrator-passphrase", salt=b"replace-with-real-salt-bytes"
        ),
        backend=InMemoryReidBackend(),
    )

    algorithm = PseudonymizationAlgorithm(
        salt_manager=salt_manager,
        pseudonym_store=pseudonym_store,
        reid_store=reid_store,
        admin_token="admin-session-demo",  # normally issued by your auth layer
        batch_size=2,
    )

    # --- Batch 1 ---
    batch_1 = [
        {"host.ip": "10.13.21.5", "user.name": "jdoe"},
        {"host.ip": "10.10.39.2", "user.name": "asmith"},
    ]

    # --- Batch 2, processed "later" ---
    batch_2 = [
        {"host.ip": "10.13.21.5", "user.name": "jdoe"},   # same IP as Batch 1
        {"host.ip": "172.16.4.9", "user.name": "rlee"},
    ]

    for i, batch in enumerate(algorithm.process(batch_1 + batch_2), start=1):
        print(f"Batch {i}:")
        for entry in batch:
            print(f"  {entry}")

    print(
        "\nCross-batch consistency check: "
        f"{pseudonym_store.get('host.ip', '10.13.21.5')} "
        "(same pseudonym in both batches)"
    )

    # --- authorized re-identification (Administrator only) ---
    pseudonym = pseudonym_store.get("host.ip", "10.13.21.5")
    original = reid_store.reidentify("admin-session-demo", pseudonym)
    print(f"Re-identified {pseudonym} -> {original}")


if __name__ == "__main__":
    main()
