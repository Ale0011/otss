# otss — one-time secret service

View-once secret sharing. Stand it up, share a link, try to break it.

```bash
export MASTER_KEY=$(openssl rand -base64 32)
docker compose up --build
# listening on :8080
```

`MASTER_KEY` is required. No default, no silent generation — a missing key exits.

## Challenge

Attack the running service. Findings that matter:

- read a secret more than `max_views` allows
- burn a secret without being able to read it
- distinguish a real id from a fake one
- bypass rate limiting
- recover content, passphrase, deletion token, or raw id from logs / metrics / memory after burn
- anything that puts those values into a log line or `/metrics`

Report with a reproducer script. A finding without one does not count.

Rules: only containers you were assigned. No shared-network or host-level attacks. Do not post a working exploit publicly before the round closes.

Threat model and out-of-scope notes: [`SECURITY.md`](SECURITY.md). Crypto and deletion design: [`DESIGN.md`](DESIGN.md).

## API

### Create — `POST /secrets`

```bash
curl -s localhost:8080/secrets -H 'Content-Type: application/json' -d '{
  "content": "the launch codes",
  "ttl_seconds": 3600,
  "max_views": 1,
  "passphrase": "optional"
}'
```

```json
{
  "id": "…",
  "url": "http://localhost:8080/s/…#p=…",
  "deletion_token": "…",
  "expires_at": "…",
  "max_views": 1
}
```

With a passphrase, the share URL puts it in the **fragment** (`#p=`). Fragments are not sent to the server.

There is also a no-JS browser form at `/` (`POST /secrets/form`).

### Read — `GET /s/{id}` / `POST /s/{id}`

Consumes a view. JSON by default; browsers (`Accept: text/html`) get HTML.

```bash
curl localhost:8080/s/$ID -H "X-Passphrase: optional"
curl -X POST localhost:8080/s/$ID -H 'Content-Type: application/json' -d '{"passphrase":"optional"}'
```

`POST /s/{id}/open` is an alias. Wrong passphrase does not consume a view.

### Revoke — `DELETE /s/{id}`

```bash
curl -X DELETE localhost:8080/s/$ID -H "X-Deletion-Token: $TOKEN"
```

### Ops — `GET /healthz`, `GET /metrics`

Liveness and Prometheus counters. Gate metrics with `METRICS_TOKEN` when exposed.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `MASTER_KEY` | *(required)* | 32 random bytes, base64 |
| `PUBLIC_BASE_URL` | loopback only | Set in any real deploy |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs; empty = trust no proxy |
| `METRICS_TOKEN` | *(empty = open)* | `Authorization: Bearer <token>` when set |
| `CREATE_RATE` / `CREATE_BURST` | 10 / 20 | Per client IP |
| `READ_RATE` / `READ_BURST` | 50 / 100 | Per client IP |
| `PORT` | 8080 | |

## Test / probe

```bash
go test ./...
./tools/attack.sh http://localhost:8080
go run ./tools/loadtest -rps 200 -duration 60s
go run ./tools/kdfbench -n 300
```

## License

MIT. See [`LICENSE`](LICENSE).
