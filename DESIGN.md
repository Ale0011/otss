# Design

Architecture notes for operators and reviewers of the code. Not a scoring guide.

## Crypto

Secrets live only in process memory as AES-256-GCM ciphertext. Each record has a
random data key (DEK). The DEK is wrapped with a key derived from `MASTER_KEY`,
the secret id, and an optional passphrase (PBKDF2-HMAC-SHA256 when a passphrase
is set). Plaintext and the passphrase are never written to disk.

`MASTER_KEY` comes from the environment. If it is missing, the process exits.

## Storage and deletion

There is no database and no volume for secret data. A successful view decrements
`views_remaining` under a per-record lock; at zero the record is removed and its
buffers are overwritten. Revocation stores only `SHA-256(deletion_token)`.

A process restart drops every live secret. That is intentional.

## HTTP surface

| Method | Path | Role |
|---|---|---|
| `POST` | `/secrets` | create (JSON) |
| `POST` | `/secrets/form` | create (browser form) |
| `GET` / `POST` | `/s/{id}` | read / unlock |
| `POST` | `/s/{id}/open` | unlock alias |
| `DELETE` | `/s/{id}` | revoke |
| `GET` | `/healthz` | liveness |
| `GET` | `/metrics` | aggregate counters |
| `GET` | `/` | no-JS UI |

Rate limits are per client IP. `TRUSTED_PROXIES` defaults to empty (socket
address only). Share links use `PUBLIC_BASE_URL` when set.

## Ops knobs that affect cost

Passphrase-protected create/read pays for KDF work. Concurrent derivations are
capped. Empty-passphrase secrets stay on the cheap path so the hot path stays
fast under load (`tools/loadtest`, `tools/kdfbench`).
