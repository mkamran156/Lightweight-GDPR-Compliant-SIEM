# Tests

These tests check the properties the paper claims of Algorithm 1. Each one
names the section or claim it exercises, so a reader can go from a statement
in the paper to the test that covers it.

## Running

From the repository root:

```bash
pip install -r src/pseudonymization/requirements.txt --break-system-packages
pip install pytest --break-system-packages
python -m pytest tests/ -v
```

## What is covered

| Test | Paper reference |
|---|---|
| `test_pseudonym_is_a_sha256_hex_digest` | Section 6.1, the primitive is HMAC-SHA-256 |
| `test_same_value_same_pseudonym_within_a_batch` | Section 4.4, the scheme is deterministic |
| `test_same_value_same_pseudonym_across_batches` | Section 4.4 and Fig. 5, cross-batch consistency |
| `test_consistency_comes_from_the_key_not_the_store` | Section 4.4, the store is a cache, not the source of stability |
| `test_different_fields_use_different_keys` | Section 4.2, per-field key separation |
| `test_batch_size_does_not_change_the_output` | Section 4.4, batching is a resource control |
| `test_non_sensitive_fields_are_left_alone` | Algorithm 1, line 3 |
| `test_reidentification_requires_an_admin_token` | Section 4.2, Administrator-only re-identification |
| `test_authorized_reidentification_round_trips` | Section 4.2 |
| `test_every_sensitive_field_has_a_key` | Algorithm 1, line 3 |
