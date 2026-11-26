# Security

Scope for the attack phase. This is not a walkthrough of the defenses.

## Threat model

Attackers may hold a share link, read container logs and `/metrics`, dump any
volume the compose file mounts, and probe the HTTP API freely.

Attackers do **not** hold `MASTER_KEY` and do not get root inside the container.

## In scope

Anything reachable over the published HTTP port that yields:

1. secret content beyond what `max_views` allows
2. a passphrase, deletion token, or raw secret id you were not given
3. existence oracles (real id vs fake / burned / expired)
4. rate-limit bypass
5. recovery of a secret after it was viewed or revoked
6. leakage of (1)–(2) into logs or `/metrics`

## Out of scope (known, not scored)

- Offline brute force of a weak passphrase after a full memory dump
- Compromise of `MASTER_KEY` itself
- Root / privileged access inside the container
- Pure volumetric DoS against the host or network
- TLS termination (deploy behind a reverse proxy; set `PUBLIC_BASE_URL`)
- Secrets vanishing on process restart (intentional — no durability)

## Reporting

Open an issue with the `security` label, or contact the maintainer. Include a
reproducer. Do not publish a working exploit before the round closes.
