# Functional Test Cases

## Overview
This document describes the functional test cases for the gRPC Test Server.

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
| TestFunctional_AuthModes_InsecureToTLSUpgrade | Insecure client to TLS server | Unavailable error |
| TestFunctional_AuthModes_TableDriven | All auth modes in table-driven format | Each mode works correctly |

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

## Test Tags
- `functional` - Functional tests (no external dependencies)
- `integration` - Integration tests (requires docker-compose services)
- `e2e` - End-to-end tests (requires full environment)
- `performance` - Performance and benchmark tests
