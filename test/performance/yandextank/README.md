# Yandex Tank gRPC Load Testing (optional / additive)

The authoritative load tests for this project are the Go-based tests under
`test/performance/` (build tag `performance`). They already cover all auth modes
(`none`/`tls`/`mtls`/`oidc`/`both`) and report throughput + latency percentiles
against the running server.

These Yandex Tank configs are **optional** and provided for teams that want an
external, RPS-scheduled load profile with Yandex Tank's reporting and autostop
machinery.

## Files

| File | Purpose |
|------|---------|
| `load.yaml` | Yandex Tank config using the Pandora engine (gRPC gun). |
| `ammo.json` | Pandora ammo describing the `Unary` RPC call + payload. |

## Prerequisites

- [Yandex Tank](https://yandextank.readthedocs.io/) installed (or its Docker image).
- [Pandora](https://github.com/yandex/pandora) binary on `PATH`.
- The grpc-example server running (docker-compose project `grpc-test`).

## Auth caveat (mTLS + OIDC)

The server enforces `AUTH_MODE=both` (mTLS client cert **and** OIDC bearer
token). The stock Pandora gRPC gun supplies a bearer token via metadata but does
**not** present a client TLS certificate, so it cannot complete the mTLS
handshake against the enforced endpoint.

To use Yandex Tank you have three options:

1. **Recommended for `both`:** use the Go load tests instead — they present both
   the client cert (from `CERT_DIR`) and a Keycloak token:
   ```bash
   CERT_DIR=/tmp/grpc-test-certs GRPC_ADDRESS=localhost:50051 \
   KEYCLOAK_URL=http://localhost:8090 KC_REALM=grpc-test \
   KC_CLIENT_ID=grpc-server KC_CLIENT_SECRET=grpc-server-secret AUTH_MODE=both \
   go test -v -tags=performance -run TestPerformance_LiveServer ./test/performance/...
   ```
2. Point `load.yaml` at a server started with `AUTH_MODE=oidc` (TLS + token only).
3. Build a custom Pandora gun with mTLS client-cert support and reference it from
   `load.yaml`.

## Acquire a bearer token

```bash
TOKEN=$(curl -s -X POST \
  "http://localhost:8090/realms/grpc-test/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=grpc-server" \
  -d "client_secret=grpc-server-secret" | \
  python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# Inject it into the ammo file (token TTL is short; refresh as needed):
sed -i '' "s/REPLACE_WITH_TOKEN/$TOKEN/" test/performance/yandextank/ammo.json
```

## Run

```bash
# Artifacts (phout.txt, charts, logs) are written under .yandextank/
yandex-tank -c test/performance/yandextank/load.yaml
```

## Load profile

`load.yaml` schedules:
- 100 → 1000 RPS ramp over 60s (warmup),
- 1000 RPS constant for 120s (steady state),
- 1000 → 3000 RPS ramp over 60s (stress).

## Autostop (safety)

The test aborts early if:
- > 5% non-OK responses over 10s,
- p99 latency > 500ms for 15s,
- average response time > 250ms for 20s.

## Analyzing results

`phout.txt` (Phantom output format) contains per-request timing and response
codes. Yandex Tank renders latency-vs-RPS and response-code-vs-RPS charts in its
web/console report. Key columns:

| Column | Meaning |
|--------|---------|
| `time` | request timestamp |
| `rt` | response time (µs) |
| `proto_code` | gRPC/HTTP status |
| `net_code` | network-level status |
