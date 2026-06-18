# Functional Test Cases

## Overview
This document describes the functional test cases for the gRPC Test Server.

## Authentication Method Coverage Axis

Every transport/RPC behaviour is validated across **all four authentication
modes**. Tests use the `AUTH_MODE` matrix below. New observability tests
(section 8) and the auth-mode table (section 7) MUST exercise each mode.

| Auth Mode | TLS | Client Cert (Vault PKI / mTLS) | Bearer Token (OIDC / Keycloak) | Notes |
|-----------|-----|--------------------------------|--------------------------------|-------|
| `none` | none | not required | not required | Insecure backward-compat baseline |
| `mtls` | mtls | required & validated | not required | Client cert subject checked |
| `oidc` | tls (server) | not required | required & validated | Token signature/issuer/audience checked |
| `both` | mtls | required & validated | required & validated | Cert AND token must both pass |

**Coverage rule:** each unary, server-stream, and bidi-stream happy path is
asserted under `none`, `mtls`, `oidc`, and `both`. Negative auth cases
(missing/invalid cert, missing/invalid token) are asserted under the modes
where that credential is required.

## Test Categories

### 1. Unary RPC Tests (`unary_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_Unary_SimpleMessage | Send a simple "Hello, gRPC!" message | Message echoed back with timestamp |
| TestFunctional_Unary_EmptyMessage | Send an empty string message | Empty string echoed back with timestamp |
| TestFunctional_Unary_LargeMessage | Send a 1KB message (1024 'A' characters) | Full message echoed back |
| TestFunctional_Unary_UnicodeMessage | Send Unicode characters | Unicode message echoed back correctly |
| TestFunctional_Unary_ConcurrentRequests | Send 10 parallel requests | All requests succeed with correct responses |
| TestFunctional_Unary_RequestWithDeadline | Send request with 5s deadline | Request completes successfully |
| TestFunctional_Unary_RequestWithExpiredDeadline | Send request with expired deadline | DeadlineExceeded error |
| TestFunctional_Unary_TableDriven | Multiple message types (ASCII, numbers, special chars, JSON) | All messages echoed correctly |

### 2. Server Streaming Tests (`server_stream_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_ServerStream_FiveValues | Request 5 values with 10ms interval | Receive exactly 5 responses |
| TestFunctional_ServerStream_ZeroValues | Request 0 values | InvalidArgument error |
| TestFunctional_ServerStream_HundredValues | Request 100 values | Receive exactly 100 responses |
| TestFunctional_ServerStream_CancelAfterThree | Cancel stream after receiving 3 values | Receive 3 values, then error on next recv |
| TestFunctional_ServerStream_SequentialSequenceNumbers | Verify sequence numbers | Sequences are 1, 2, 3, 4, 5 |
| TestFunctional_ServerStream_IncreasingTimestamps | Verify timestamps | Each timestamp > previous |
| TestFunctional_ServerStream_CustomInterval | Request with 100ms interval | Takes at least 300ms for 3 values |
| TestFunctional_ServerStream_RandomValues | Request 10 values | Values are not all identical |
| TestFunctional_ServerStream_TableDriven | Various count/interval combinations | Correct behavior for each case |

### 3. Bidirectional Streaming Tests (`bidi_stream_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_BidiStream_FiveValuesTransformed | Send 5 values with double operation | Receive 5 transformed responses |
| TestFunctional_BidiStream_DoubleOperation | Test double operation with various values | value * 2 for each |
| TestFunctional_BidiStream_SquareOperation | Test square operation with various values | value * value for each |
| TestFunctional_BidiStream_NegateOperation | Test negate operation with various values | -value for each |
| TestFunctional_BidiStream_MixedOperations | Mix of double, square, negate | Correct transformation for each |
| TestFunctional_BidiStream_ZeroValues | Close stream without sending | Receive EOF immediately |
| TestFunctional_BidiStream_RapidSendWithoutWaiting | Send 50 values rapidly | All 50 responses received correctly |
| TestFunctional_BidiStream_CloseSendAndReceiveRemaining | Close send, then receive | All pending responses received |
| TestFunctional_BidiStream_CancelMidStream | Cancel context mid-stream | Canceled error on subsequent operations |
| TestFunctional_BidiStream_InvalidOperation | Send invalid operation | InvalidArgument error |
| TestFunctional_BidiStream_TableDriven | Various operation/value combinations | Correct results for each case |

### 4. Error Scenario Tests (`error_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_Error_ConnectToWrongPort | Connect to non-listening port | Unavailable error |
| TestFunctional_Error_RequestTimeout | Request with 1ns timeout | DeadlineExceeded error |
| TestFunctional_Error_ServerShutdownMidRequest | Stop server during streaming | Unavailable/Canceled/Internal error |
| TestFunctional_Error_StreamCancellation | Cancel stream context | Canceled error |
| TestFunctional_Error_InvalidStreamParameters | Invalid count/interval values | InvalidArgument error |
| TestFunctional_Error_BidiStreamInvalidOperation | Unknown operation in bidi stream | InvalidArgument error |
| TestFunctional_Error_ContextCancelledBeforeRequest | Pre-cancelled context | Canceled error |
| TestFunctional_Error_MultipleErrors | Multiple error scenarios in sequence | Each error handled correctly |

### 5. mTLS Authentication Tests (`mtls_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_MTLS_ValidClientCertificate | Client with valid cert signed by server CA | Request succeeds, message echoed |
| TestFunctional_MTLS_InvalidClientCertificate | Client with cert signed by wrong CA | Unavailable error (TLS handshake fails) |
| TestFunctional_MTLS_ExpiredClientCertificate | Client with expired certificate | Unavailable error (TLS handshake fails) |
| TestFunctional_MTLS_WrongCASignedCertificate | Client cert from completely different CA | Unavailable error (TLS handshake fails) |
| TestFunctional_MTLS_MissingClientCertificate | Client connects without any certificate | Unavailable error (TLS handshake fails) |
| TestFunctional_MTLS_CertificateWithWrongSubject | Client cert CN not in AllowedSubjects | Unauthenticated error from interceptor |
| TestFunctional_MTLS_CertificateWithAllowedSubject | Client cert CN matches AllowedSubjects | Request succeeds |
| TestFunctional_MTLS_AllGRPCMethods_Unary | Unary RPC with valid mTLS | Request succeeds |
| TestFunctional_MTLS_AllGRPCMethods_ServerStream | Server streaming with valid mTLS | Stream completes with 3 responses |
| TestFunctional_MTLS_AllGRPCMethods_BidiStream | Bidi streaming with valid mTLS | Bidirectional exchange succeeds |
| TestFunctional_MTLS_MultipleClientsWithDifferentCerts | 3 clients with different certs | All clients succeed |
| TestFunctional_MTLS_TableDriven | Valid, expired, wrong CA, no cert | Correct behavior for each |
| TestFunctional_MTLS_FutureClientCertificate | Client cert not yet valid (future NotBefore) | Unavailable error |
| TestFunctional_MTLS_SelfSignedClientCertificate | Self-signed client cert (not from server CA) | Unavailable error |
| TestFunctional_MTLS_ServerWithIPSAN | Server cert with IP SAN, client connects | Request succeeds |

### 6. OIDC Authentication Tests (`oidc_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_OIDC_ValidToken | Valid bearer token in metadata | Request succeeds, message echoed |
| TestFunctional_OIDC_InvalidToken | Token with invalid signature | Unauthenticated error |
| TestFunctional_OIDC_ExpiredToken | Expired token | Unauthenticated error |
| TestFunctional_OIDC_TokenWithWrongAudience | Token audience doesn't match config | Unauthenticated error with audience message |
| TestFunctional_OIDC_TokenWithWrongIssuer | Token issuer doesn't match | Unauthenticated error |
| TestFunctional_OIDC_MissingToken | No authorization metadata | Unauthenticated error |
| TestFunctional_OIDC_TokenWithRequiredClaims | Token with role and scope claims | Request succeeds |
| TestFunctional_OIDC_AllGRPCMethods_Unary | Unary RPC with valid OIDC token | Request succeeds |
| TestFunctional_OIDC_AllGRPCMethods_ServerStream | Server streaming with valid OIDC token | Stream completes |
| TestFunctional_OIDC_AllGRPCMethods_BidiStream | Bidi streaming with valid OIDC token | Exchange succeeds |
| TestFunctional_OIDC_EmptyBearerToken | "Bearer " with empty token value | Unauthenticated error |
| TestFunctional_OIDC_TableDriven | Valid, invalid, expired, wrong audience, missing | Correct behavior for each |

### 7. Auth Mode Tests (`auth_modes_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_AuthModes_InsecureMode | No TLS, no auth (backward compat) | Request succeeds |
| TestFunctional_AuthModes_TLSOnly | TLS enabled, no client auth | Request succeeds with TLS client |
| TestFunctional_AuthModes_MTLSMode | mTLS with valid client cert | Request succeeds |
| TestFunctional_AuthModes_OIDCMode | OIDC with valid bearer token | Request succeeds |
| TestFunctional_AuthModes_CombinedMTLSAndOIDC | Both mTLS cert and OIDC token | Request succeeds |
| TestFunctional_AuthModes_CombinedMTLSAndOIDC_MissingToken | mTLS cert but no OIDC token | Unauthenticated error |
| TestFunctional_AuthModes_CombinedMTLSAndOIDC_MissingCert | OIDC token but no client cert | Unavailable error (TLS handshake fails) |
| TestFunctional_AuthModes_InsecureToTLSUpgrade | Insecure client to TLS server | Unavailable error |
| TestFunctional_AuthModes_AllModes_Unary | Unary RPC under none/mtls/oidc/both | Request succeeds in each mode |
| TestFunctional_AuthModes_AllModes_ServerStream | Server stream under none/mtls/oidc/both | Stream completes in each mode |
| TestFunctional_AuthModes_AllModes_BidiStream | Bidi stream under none/mtls/oidc/both | Exchange succeeds in each mode |
| TestFunctional_AuthModes_TableDriven | All auth modes in table-driven format | Each mode works correctly |

**Acceptance criteria (auth modes):**
- Every RPC type (unary, server-stream, bidi-stream) passes under all four
  modes: `none`, `mtls`, `oidc`, `both`.
- `none` mode keeps working with no TLS and no credentials (backward compat).
- `both` mode requires BOTH a valid client cert AND a valid bearer token;
  removing either credential yields the appropriate failure.

### 8. Metrics & Observability Tests (`metrics_test.go`)

These tests validate the additive Prometheus metrics and the gated OTLP
metrics export. Existing metrics (`grpc_server_started_total`,
`grpc_server_handled_total`, `grpc_server_handling_seconds`,
`auth_attempts_total`) MUST remain unchanged in name and labels.

#### Prometheus metrics

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_Metrics_ExistingMetricsUnchanged | Gather default registry | `grpc_server_started_total`, `grpc_server_handled_total`, `grpc_server_handling_seconds`, `auth_attempts_total` present with original labels |
| TestFunctional_Metrics_StartedAndHandledIncrement | Issue N unary RPCs | `started_total` and `handled_total{grpc_code="OK"}` increase by N |
| TestFunctional_Metrics_InFlightGaugeReturnsToZero | Issue balanced RPCs (incl. streaming) | `grpc_server_in_flight_requests` returns to 0 after completion |
| TestFunctional_Metrics_MsgSentReceivedCounters | Server-stream of K msgs, bidi of M msgs | `grpc_server_msg_sent_total` / `grpc_server_msg_received_total` reflect message counts |
| TestFunctional_Metrics_AuthAttempts_MTLS | Valid + invalid mTLS attempt | `auth_attempts_total{auth_type="mtls",result="success"}` and `{result="failure"}` increment |
| TestFunctional_Metrics_AuthAttempts_OIDC | Valid + invalid OIDC attempt | `auth_attempts_total{auth_type="oidc",result="success"}` and `{result="failure"}` increment |
| TestFunctional_Metrics_AuthAttempts_None | Insecure mode requests | No `auth_attempts_total` increments (no auth performed) |
| TestFunctional_Metrics_AuthAttempts_Both | `both` mode valid + invalid | Auth attempts recorded for the executed method(s) |
| TestFunctional_Metrics_AuthLatencyHistogram | Auth attempt under mtls/oidc | `auth_attempt_duration_seconds` observed (count increases) |
| TestFunctional_Metrics_EndpointServesMetrics | GET `/metrics` | HTTP 200; body contains all expected metric names |
| TestFunctional_Metrics_HealthzEndpoint | GET `/healthz` | HTTP 200 "ok" |

#### OTLP metrics export (gated)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_OTLP_DisabledIsNoOp | OTEL disabled / empty endpoint | No meter provider set; no error; `/metrics` still authoritative |
| TestFunctional_OTLP_EnabledInitNoError | OTEL enabled with endpoint | Meter provider initialized without error |
| TestFunctional_OTLP_PrometheusUnaffected | OTEL enabled | `/metrics` output identical in shape to OTLP-off run (no double registration) |
| TestFunctional_OTLP_ShutdownNoPanic | Init then shutdown meter+tracer | Graceful shutdown, no panic, flush logged |

**Acceptance criteria (metrics & observability):**
- New metrics are additive; the four pre-existing metrics keep identical
  names, label sets, and help text.
- In-flight gauge is balanced (returns to 0) over a complete request
  lifecycle including streaming and error paths.
- `auth_attempts_total` is incremented at every auth decision for `mtls`
  and `oidc` (and within `both`); `none` records no auth attempts.
- OTLP metrics export is a pure no-op when disabled or endpoint is empty;
  when enabled it must not interfere with the Prometheus pull endpoint,
  which remains authoritative.
- Assertions use gathered-registry deltas (before/after) rather than
  absolute counts, to remain stable under parallel test execution.

## Test Execution

### Run All Functional Tests
```bash
go test -v -race -tags=functional ./test/functional/...
```

### Run Specific Test Category
```bash
# mTLS tests only
go test -v -race -tags=functional ./test/functional/... -run TestFunctional_MTLS

# OIDC tests only
go test -v -race -tags=functional ./test/functional/... -run TestFunctional_OIDC

# Auth mode tests only
go test -v -race -tags=functional ./test/functional/... -run TestFunctional_AuthModes

# Metrics & observability tests only
go test -v -race -tags=functional ./test/functional/... -run TestFunctional_Metrics

# OTLP metrics export tests only
go test -v -race -tags=functional ./test/functional/... -run TestFunctional_OTLP
```

### Run Integration Tests (requires docker-compose)
```bash
go test -v -race -tags=integration ./test/integration/...
```

### Run E2E Tests (requires full environment)
```bash
go test -v -race -tags=e2e ./test/e2e/...
```

### Run Performance Tests
```bash
go test -v -tags=performance -bench=. ./test/performance/...
```

### Run With Coverage
```bash
go test -v -race -tags=functional -coverprofile=coverage.out ./test/functional/...
go tool cover -html=coverage.out
```

## Test Infrastructure

### Suite Setup (`suite_test.go`)
- Starts a real gRPC server on a random available port
- Creates a gRPC client connection
- Provides helper functions for test context creation
- Supports different auth modes (insecure, TLS, mTLS, OIDC)
- Certificate generation helpers for mTLS tests
- Token generation helpers for OIDC tests
- Cleans up resources after all tests complete

### Test Service (`test_service.go`)
- Implements the TestServiceServer interface
- Mirrors the production service implementation
- Used by the test suite for functional testing

### Auth Test Helpers
- `testCA` - Self-signed CA for generating test certificates
- `mtlsTestEnv` - Complete mTLS test environment (CA, server, certs)
- `oidcTestEnv` - Complete OIDC test environment (mock provider, server)
- `mockTokenVerifier` / `mockProvider` - Mock OIDC components
- `contextWithBearerToken` - Helper to add bearer tokens to gRPC context

### Metrics / Observability Test Helpers
- Gather-and-diff helper around `prometheus.DefaultGatherer.Gather()` to
  assert metric deltas independent of other parallel tests.
- Helper to start the metrics HTTP server on a random port and scrape
  `/metrics` and `/healthz`.
- OTLP test helper using a manual/in-memory metric reader (or a stub
  collector endpoint) to assert export init/shutdown without a live backend.

## Test Tags
- `functional` - Functional tests (no external dependencies)
- `integration` - Integration tests (requires docker-compose services)
- `e2e` - End-to-end tests (requires full environment)
- `performance` - Performance and benchmark tests
