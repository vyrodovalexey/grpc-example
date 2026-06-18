# gRPC Test Server

[![CI](https://github.com/vyrodovalexey/grpc-example/actions/workflows/ci.yml/badge.svg)](https://github.com/vyrodovalexey/grpc-example/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/alexey/grpc-example/branch/main/graph/badge.svg)](https://codecov.io/gh/alexey/grpc-example)
[![Go Version](https://img.shields.io/badge/go-1.26.4-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A comprehensive gRPC test server implementation in Go, designed for testing and development purposes. This server provides three different types of gRPC endpoints to demonstrate various communication patterns with advanced authentication capabilities.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Observability](#observability)
- [Configuration](#configuration)
- [Test Environment](#test-environment)
- [API Reference](#api-reference)
- [Development](#development)
- [Docker](#docker)
- [Kubernetes Deployment](#kubernetes-deployment)
- [CI/CD](#cicd)
- [License](#license)

## Overview

This project implements a gRPC test server with three endpoint types:

- **Unary RPC** - Simple request-response pattern
- **Server Streaming RPC** - Server sends multiple responses for a single request
- **Bidirectional Streaming RPC** - Both client and server can send multiple messages

The server is built with production-ready features including structured logging, graceful shutdown, comprehensive testing, Docker support, and advanced authentication capabilities.

## Features

- ✅ Three gRPC endpoint types (Unary, Server Streaming, Bidirectional Streaming)
- ✅ **mTLS authentication** with certificate-based client verification
- ✅ **OIDC authentication** with OpenID Connect token validation
- ✅ **Vault PKI integration** for automated certificate management
- ✅ **Keycloak integration** for identity and access management
- ✅ **Prometheus metrics** with gRPC, auth, Vault PKI, and OIDC metrics plus health endpoints
- ✅ **OpenTelemetry** with OTLP/HTTP export for both traces and metrics
- ✅ **Helm chart** for Kubernetes deployment
- ✅ **Performance benchmarks** with ~13k req/s throughput
- ✅ Structured JSON logging with configurable levels
- ✅ Graceful shutdown with configurable timeout
- ✅ Comprehensive unit, functional, integration, and e2e tests
- ✅ Docker support with multi-stage builds
- ✅ CI/CD pipelines with GitHub Actions
- ✅ Code quality checks (linting, vulnerability scanning)
- ✅ Coverage reporting with Codecov
- ✅ SonarCloud integration for code analysis
- ✅ Automated releases with GitHub Releases

## Prerequisites

- **Go 1.26.4+** - [Download](https://golang.org/dl/)
- **Protocol Buffers Compiler (protoc)** - [Installation Guide](https://grpc.io/docs/protoc-installation/)
- **Docker and Docker Compose** (for test environment) - [Download](https://www.docker.com/get-started)

### Install Required Tools

```bash
# Install development tools
make tools

# Or install manually
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
go install golang.org/x/vuln/cmd/govulncheck@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
go install golang.org/x/tools/cmd/goimports@latest
```

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/vyrodovalexey/grpc-example.git
cd grpc-example
```

### 2. Build and Run

```bash
# Generate protobuf code, run tests, and build
make all

# Run the server (no authentication)
make run
```

The server will start on `localhost:50051` by default.

### 3. Test with grpcurl

Install grpcurl if you haven't already:

```bash
# macOS
brew install grpcurl

# Linux
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

Test the endpoints:

```bash
# Test Unary RPC
grpcurl -plaintext -d '{"message": "Hello, World!"}' \
  localhost:50051 api.v1.TestService/Unary

# Test Server Streaming RPC
grpcurl -plaintext -d '{"count": 5, "interval_ms": 1000}' \
  localhost:50051 api.v1.TestService/ServerStream

# Test Bidirectional Streaming RPC (requires interactive mode)
grpcurl -plaintext localhost:50051 api.v1.TestService/BidirectionalStream
```

## Authentication

The server supports multiple authentication modes to meet different security requirements.

### Authentication Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `none` | No authentication (default) | Development, backward compatibility |
| `mtls` | Mutual TLS authentication via Vault PKI client certificate verification | High-security environments, service-to-service |
| `oidc` | OpenID Connect bearer token authentication via Keycloak | User authentication, web applications |
| `both` | Combined mTLS + OIDC (client must present a valid certificate **and** a valid bearer token) | Maximum security, enterprise environments |

#### How Clients Authenticate

| Mode | Client Requirement |
|------|--------------------|
| `none` | No credentials required. Connect with plaintext (`grpcurl -plaintext`). |
| `mtls` | Present a client certificate signed by the trusted CA (the Vault PKI CA). The server verifies the certificate chain. |
| `oidc` | Send a valid JWT in the `Authorization: Bearer <token>` metadata. The server validates the token against the issuer's public keys. |
| `both` | Present **both** a valid client certificate **and** a valid bearer token. Both checks must pass. |

### mTLS Configuration

Mutual TLS provides certificate-based authentication where both client and server verify each other's identity.

#### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `TLS_ENABLED` | Enable TLS/mTLS | `false` | `true` |
| `TLS_MODE` | TLS mode | `server` | `server`, `mutual` |
| `TLS_CERT_PATH` | Server certificate path | | `/certs/server.crt` |
| `TLS_KEY_PATH` | Server private key path | | `/certs/server.key` |
| `TLS_CA_PATH` | CA certificate path | | `/certs/ca.crt` |
| `TLS_CLIENT_AUTH` | Client auth requirement | `NoClientCert` | `RequireAndVerifyClientCert` |

#### Certificate Requirements

- **Server Certificate**: Must include server hostname/IP in SAN
- **Client Certificate**: Required for mTLS, must be signed by trusted CA
- **CA Certificate**: Used to verify client certificates

#### Vault PKI Integration

Automatically generate and manage certificates using HashiCorp Vault:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `VAULT_ENABLED` | Enable Vault PKI | `false` | `true` |
| `VAULT_ADDR` | Vault server address | | `https://vault.example.com:8200` |
| `VAULT_TOKEN` | Vault authentication token | | `hvs.CAESIJ...` |
| `VAULT_PKI_PATH` | PKI secrets engine path | `pki` | `pki_int` |
| `VAULT_PKI_ROLE` | PKI role name | `server` | `grpc-server` |
| `VAULT_PKI_TTL` | Certificate TTL | `24h` | `168h` |

#### Example mTLS Setup

```bash
# Enable mTLS with Vault PKI
export AUTH_MODE=mtls
export TLS_ENABLED=true
export TLS_MODE=mutual
export TLS_CLIENT_AUTH=RequireAndVerifyClientCert
export VAULT_ENABLED=true
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.CAESIJ...
export VAULT_PKI_ROLE=grpc-server

./bin/grpc-server
```

### OIDC Configuration

OpenID Connect provides token-based authentication using JWT tokens from an identity provider.

#### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OIDC_ENABLED` | Enable OIDC authentication | `false` | `true` |
| `OIDC_ISSUER_URL` | OIDC issuer URL | | `https://keycloak.example.com/realms/grpc` |
| `OIDC_CLIENT_ID` | OIDC client ID | | `grpc-server` |
| `OIDC_CLIENT_SECRET` | OIDC client secret | | `grpc-server-secret` |
| `OIDC_AUDIENCE` | Expected token audience | | `grpc-api` |

#### Keycloak Integration

The server integrates with Keycloak for identity and access management:

1. **Realm Setup**: Create a realm for your gRPC services
2. **Client Configuration**: Configure a confidential client with service account enabled
3. **Token Validation**: Server validates JWT tokens against Keycloak's public keys

#### Token Requirements

- **Format**: JWT (JSON Web Token)
- **Header**: Include in `Authorization: Bearer <token>` header
- **Claims**: Must include valid `iss`, `aud`, `exp`, and `sub` claims
- **Signature**: Must be signed by trusted issuer

#### Example OIDC Setup

```bash
# Enable OIDC authentication
export AUTH_MODE=oidc
export OIDC_ENABLED=true
export OIDC_ISSUER_URL=https://keycloak.example.com/realms/grpc
export OIDC_CLIENT_ID=grpc-server
export OIDC_CLIENT_SECRET=grpc-server-secret
export OIDC_AUDIENCE=grpc-api

./bin/grpc-server
```

#### Testing with OIDC

```bash
# Get token from Keycloak
TOKEN=$(curl -s -X POST \
  "https://keycloak.example.com/realms/grpc/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=grpc-server" \
  -d "client_secret=grpc-server-secret" | jq -r '.access_token')

# Use token with grpcurl
grpcurl -plaintext \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message": "Hello, World!"}' \
  localhost:50051 api.v1.TestService/Unary
```

## Observability

The server provides comprehensive observability features including Prometheus metrics and OpenTelemetry tracing for monitoring and debugging.

### Prometheus Metrics

The server exposes Prometheus metrics on a separate HTTP port (default 9090) to provide insights into gRPC server performance and health.

#### Available Endpoints

- **`/metrics`** - Prometheus metrics endpoint for scraping
- **`/healthz`** - Health check endpoint (returns 200 OK when healthy)

#### Available Metrics

**gRPC server metrics** (labels: `grpc_type`, `grpc_service`, `grpc_method`):

| Metric | Type | Description |
|--------|------|-------------|
| `grpc_server_started_total` | Counter | Total number of RPCs started on the server |
| `grpc_server_handled_total` | Counter | Total number of RPCs completed (adds the `grpc_code` label) |
| `grpc_server_handling_seconds` | Histogram | Histogram of response latency (seconds) of handled RPCs |
| `grpc_server_in_flight_requests` | Gauge | Number of RPCs currently being handled by the server |
| `grpc_server_msg_received_total` | Counter | Total number of stream messages received by the server |
| `grpc_server_msg_sent_total` | Counter | Total number of stream messages sent by the server |

**Authentication metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_attempts_total` | Counter | `auth_type`, `result` | Total authentication attempts |
| `auth_attempt_duration_seconds` | Histogram | `auth_type`, `result` | Authentication attempt latency |

**Vault PKI metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vault_pki_operations_total` | Counter | `operation`, `result` | Total Vault PKI operations |
| `vault_pki_operation_duration_seconds` | Histogram | `operation` | Vault PKI operation latency |

**OIDC metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `oidc_verification_total` | Counter | `result` | Total OIDC token verifications |
| `oidc_provider_requests_total` | Counter | `operation`, `result` | Total OIDC provider requests (discovery, JWKS, health) |

Label values: `auth_type` is one of `mtls` or `oidc`; `result` is one of `success` or `failure`.

#### Example Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'grpc-server'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    metrics_path: /metrics
```

#### Example Grafana Queries

```promql
# Request rate per second
rate(grpc_server_started_total[5m])

# Request duration 95th percentile
histogram_quantile(0.95, rate(grpc_server_handling_seconds_bucket[5m]))

# Error rate
rate(grpc_server_handled_total{grpc_code!="OK"}[5m]) / rate(grpc_server_handled_total[5m])

# Authentication success rate
rate(auth_attempts_total{result="success"}[5m]) / rate(auth_attempts_total[5m])
```

### OpenTelemetry (Traces and Metrics)

The server supports OpenTelemetry over OTLP/HTTP for integration with collectors and backends
like Jaeger, Tempo, the OpenTelemetry Collector, or cloud providers. When enabled, the server
exports **both distributed traces and metrics** via OTLP/HTTP.

The Prometheus pull endpoint (`/metrics` on `METRICS_PORT`) remains the authoritative source of
truth for metrics. OTLP metrics export is an additive push pipeline and never touches the
Prometheus registry. Metrics are pushed periodically (every 15 seconds).

#### Configuration

OpenTelemetry is configured via environment variables and is enabled only when `OTEL_ENABLED=true`
**and** `OTEL_EXPORTER_OTLP_ENDPOINT` is set:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OTEL_ENABLED` | Enable OpenTelemetry traces and metrics export | `false` | `true` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP endpoint as `host:port` (no scheme) | | `localhost:4318` |
| `OTEL_SERVICE_NAME` | Service name for traces and metrics | `grpc-example-server` | `my-grpc-server` |

> **Endpoint format**: The OTLP/HTTP exporters use `host:port` without a URL scheme (the default
> OTLP/HTTP port is `4318`). The connection is **insecure** (plaintext HTTP) by default in this setup.

#### Features

- **Traces**: Automatic gRPC instrumentation via `otelgrpc.NewServerHandler()` for span creation
- **Metrics**: OTLP/HTTP metrics export via a periodic reader (15s interval) using `otlpmetrichttp`
- **Trace Propagation**: Supports W3C TraceContext and Baggage propagation
- **No-op by Default**: Both traces and metrics export are disabled when no endpoint is configured (zero overhead)
- **OTLP/HTTP Export**: Compatible with any OTLP/HTTP-compatible collector or backend

#### Example with Jaeger

```bash
# Start Jaeger (all-in-one)
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 14250:14250 \
  -p 4317:4317 \
  -p 4318:4318 \
  jaegertracing/all-in-one:latest

# Configure server with OpenTelemetry (note: host:port, no scheme)
export OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4318
export OTEL_SERVICE_NAME=grpc-server

./bin/grpc-server
```

#### Example with the OpenTelemetry Collector

```bash
# Configure server to push traces and metrics to a collector
export OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4318
export OTEL_SERVICE_NAME=grpc-server

./bin/grpc-server
```

### Environment Variables Summary

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `METRICS_PORT` | Metrics HTTP server port | `9090` | `8080` |
| `OTEL_ENABLED` | Enable OpenTelemetry traces and metrics export | `false` | `true` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP endpoint as `host:port` (no scheme) | | `localhost:4318` |
| `OTEL_SERVICE_NAME` | Service name for traces and metrics | `grpc-example-server` | `my-grpc-server` |

## Configuration

The server can be configured using environment variables:

### Core Configuration

| Variable | Description | Default | Valid Values |
|----------|-------------|---------|--------------|
| `GRPC_PORT` | gRPC server port | `50051` | `1-65535` |
| `METRICS_PORT` | Metrics server port | `9090` | `1-65535` |
| `LOG_LEVEL` | Logging level | `info` | `debug`, `info`, `warn`, `error` |
| `SHUTDOWN_TIMEOUT` | Graceful shutdown timeout | `30s` | Duration string (e.g., `30s`, `1m`) |
| `ENABLE_REFLECTION` | Enable gRPC reflection | `true` | `true`, `false` |

### Observability Configuration

| Variable | Description | Default | Valid Values |
|----------|-------------|---------|--------------|
| `OTEL_ENABLED` | Enable OpenTelemetry traces and metrics export | `false` | `true`, `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP endpoint as `host:port` (no scheme) | | `host:port` (e.g., `localhost:4318`) |
| `OTEL_SERVICE_NAME` | Service name for traces and metrics | `grpc-example-server` | String |

### Authentication Configuration

| Variable | Description | Default | Valid Values |
|----------|-------------|---------|--------------|
| `AUTH_MODE` | Authentication mode | `none` | `none`, `mtls`, `oidc`, `both` |

### TLS/mTLS Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `TLS_ENABLED` | Enable TLS/mTLS | `false` | `true` |
| `TLS_MODE` | TLS mode | `server` | `server`, `mutual` |
| `TLS_CERT_PATH` | Server certificate path | | `/certs/server.crt` |
| `TLS_KEY_PATH` | Server private key path | | `/certs/server.key` |
| `TLS_CA_PATH` | CA certificate path | | `/certs/ca.crt` |
| `TLS_CLIENT_AUTH` | Client auth requirement | `NoClientCert` | `RequireAndVerifyClientCert` |

### Vault PKI Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `VAULT_ENABLED` | Enable Vault PKI | `false` | `true` |
| `VAULT_ADDR` | Vault server address | | `https://vault.example.com:8200` |
| `VAULT_TOKEN` | Vault authentication token | | `hvs.CAESIJ...` |
| `VAULT_PKI_PATH` | PKI secrets engine path | `pki` | `pki_int` |
| `VAULT_PKI_ROLE` | PKI role name | `server` | `grpc-server` |
| `VAULT_PKI_TTL` | Certificate TTL | `24h` | `168h` |

### OIDC Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OIDC_ENABLED` | Enable OIDC authentication | `false` | `true` |
| `OIDC_ISSUER_URL` | OIDC issuer URL | | `https://keycloak.example.com/realms/grpc` |
| `OIDC_CLIENT_ID` | OIDC client ID | | `grpc-server` |
| `OIDC_CLIENT_SECRET` | OIDC client secret | | `grpc-server-secret` |
| `OIDC_AUDIENCE` | Expected token audience | | `grpc-api` |

### Example Configuration

```bash
# Combined mTLS + OIDC authentication
export AUTH_MODE=both
export GRPC_PORT=8080
export LOG_LEVEL=debug
export SHUTDOWN_TIMEOUT=60s

# TLS Configuration
export TLS_ENABLED=true
export TLS_MODE=mutual
export TLS_CLIENT_AUTH=RequireAndVerifyClientCert

# Vault PKI
export VAULT_ENABLED=true
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.CAESIJ...
export VAULT_PKI_ROLE=grpc-server

# OIDC
export OIDC_ENABLED=true
export OIDC_ISSUER_URL=https://keycloak.example.com/realms/grpc
export OIDC_CLIENT_ID=grpc-server
export OIDC_CLIENT_SECRET=grpc-server-secret

./bin/grpc-server
```

## Test Environment

A complete test environment is provided using Docker Compose
(`test/docker-compose/docker-compose.yml`). It provisions everything needed to exercise the
authentication flows end to end:

- **Vault** — issues mTLS certificates via the PKI secrets engine
- **Keycloak** — OIDC identity provider that issues bearer tokens
- **PostgreSQL** — backing database for Keycloak
- **grpc-server** — the application under test, built from the local source

The test environment defaults to `AUTH_MODE=both`, so the server enforces **both** mTLS (Vault
PKI) and OIDC (Keycloak) for the strongest end-to-end assertions. Keycloak is configured with a
**fixed issuer** (`KC_HOSTNAME=http://keycloak:8090`) so the OIDC `iss` claim is stable whether
tokens are validated from inside Docker or from the host. Override `AUTH_MODE` per run to exercise
a single mechanism (for example `AUTH_MODE=mtls OIDC_ENABLED=false`).

Defaults for the environment live in `test/docker-compose/.env.test`.

### Starting the Test Environment

```bash
# Start all services (Vault, Keycloak, PostgreSQL, grpc-server)
make test-env-up

# Wait for all services to become healthy
make test-env-wait

# Check service status
make test-env-status

# View logs (use SVC=<name> for a single service)
make test-env-logs

# Stop all services
make test-env-down

# Stop services and remove volumes
make test-env-clean
```

### Available Services

| Service | Port | Description | Access |
|---------|------|-------------|--------|
| **Vault** | 8200 | HashiCorp Vault for PKI | http://localhost:8200 |
| **Keycloak** | 8090 | Identity and Access Management (issuer: `http://keycloak:8090`) | http://localhost:8090 |
| **Keycloak Health** | 8091 | Keycloak health endpoint | http://localhost:8091 |
| **PostgreSQL** | 5432 | Database for Keycloak | localhost:5432 |
| **grpc-server** | 50051 / 9090 | Application under test (gRPC / metrics) | localhost:50051 |

### Default Credentials

- **Vault Root Token**: `myroot`
- **Keycloak Admin**: `admin` / `admin`
- **Keycloak Realm**: `grpc-test`
- **OIDC Client**: `grpc-server` / `grpc-server-secret`
- **PostgreSQL**: `keycloak` / `password`

### Running Different Test Types

The integration, e2e, and performance targets automatically start the test environment
(`test-env-up`) and wait for it to be healthy (`test-env-wait`) before running.

```bash
# Unit tests (no external dependencies)
make test-unit

# Functional tests (basic server functionality)
make test-functional

# Integration tests (with test environment)
make test-integration

# End-to-end tests (full authentication flows)
make test-e2e

# Performance tests (load testing)
make test-performance

# Run all tests
make test
```

## API Reference

### Service Definition

The gRPC service is defined in `api/proto/v1/test.proto`:

```protobuf
service TestService {
  rpc Unary(UnaryRequest) returns (UnaryResponse);
  rpc ServerStream(StreamRequest) returns (stream StreamResponse);
  rpc BidirectionalStream(stream BidirectionalRequest) returns (stream BidirectionalResponse);
}
```

### 1. Unary RPC

Simple request-response pattern that echoes the input message with a timestamp.

**Request:**
```json
{
  "message": "Hello, World!"
}
```

**Response:**
```json
{
  "message": "Hello, World!",
  "timestamp": 1642781234567
}
```

**Example:**
```bash
grpcurl -plaintext -d '{"message": "Test message"}' \
  localhost:50051 api.v1.TestService/Unary
```

### 2. Server Streaming RPC

Server sends multiple responses based on the count and interval specified in the request.

**Request:**
```json
{
  "count": 5,
  "interval_ms": 1000
}
```

**Response Stream:**
```json
{"value": 1, "sequence": 1, "timestamp": 1642781234567}
{"value": 2, "sequence": 2, "timestamp": 1642781235567}
{"value": 3, "sequence": 3, "timestamp": 1642781236567}
{"value": 4, "sequence": 4, "timestamp": 1642781237567}
{"value": 5, "sequence": 5, "timestamp": 1642781238567}
```

**Example:**
```bash
grpcurl -plaintext -d '{"count": 3, "interval_ms": 500}' \
  localhost:50051 api.v1.TestService/ServerStream
```

### 3. Bidirectional Streaming RPC

Both client and server can send multiple messages. The server performs mathematical operations on received values.

**Request Stream:**
```json
{"value": 10, "operation": "square"}
{"value": 5, "operation": "double"}
{"value": 8, "operation": "increment"}
```

**Response Stream:**
```json
{"original_value": 10, "transformed_value": 100, "operation": "square", "timestamp": 1642781234567}
{"original_value": 5, "transformed_value": 10, "operation": "double", "timestamp": 1642781235567}
{"original_value": 8, "transformed_value": 9, "operation": "increment", "timestamp": 1642781236567}
```

**Supported Operations:**
- `square` - Returns value²
- `double` - Returns value × 2
- `increment` - Returns value + 1
- `decrement` - Returns value - 1
- `negate` - Returns -value

**Example:**
```bash
# Interactive mode - type JSON messages and press Enter
grpcurl -plaintext localhost:50051 api.v1.TestService/BidirectionalStream
# Then type: {"value": 10, "operation": "square"}
```

### Message Definitions

```protobuf
message UnaryRequest {
  string message = 1;
}

message UnaryResponse {
  string message = 1;
  int64 timestamp = 2;
}

message StreamRequest {
  int32 count = 1;
  int32 interval_ms = 2;
}

message StreamResponse {
  int64 value = 1;
  int32 sequence = 2;
  int64 timestamp = 3;
}

message BidirectionalRequest {
  int64 value = 1;
  string operation = 2;
}

message BidirectionalResponse {
  int64 original_value = 1;
  int64 transformed_value = 2;
  string operation = 3;
  int64 timestamp = 4;
}
```

## Development

### Project Structure

```
.
├── api/proto/v1/          # Protocol buffer definitions
├── cmd/server/            # Application entry point
├── internal/
│   ├── auth/             # Authentication implementations
│   ├── config/           # Configuration management
│   ├── logger/           # Structured logging
│   ├── metrics/          # Prometheus metrics and HTTP server
│   ├── retry/            # Retry with exponential backoff
│   ├── server/           # gRPC server implementation
│   ├── service/          # Business logic
│   ├── telemetry/        # OpenTelemetry tracing
│   └── tls/              # TLS configuration and Vault PKI
├── pkg/api/v1/           # Generated protobuf code
├── helm/
│   └── grpc-server/      # Helm chart for Kubernetes deployment
├── test/
│   ├── functional/       # Functional tests
│   ├── integration/      # Integration tests
│   ├── e2e/             # End-to-end tests
│   ├── performance/      # Performance tests
│   ├── cases/           # Test case definitions
│   └── docker-compose/  # Test environment configuration
├── .github/workflows/    # CI/CD pipelines
├── Dockerfile           # Docker build configuration
├── Makefile            # Build automation
└── go.mod              # Go module definition
```

### Building from Source

```bash
# Download dependencies
make deps

# Generate protobuf code
make proto

# Build binary
make build

# Build for Linux (useful for Docker)
make build-linux
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test categories
make test-unit          # Unit tests
make test-functional    # Functional tests
make test-integration   # Integration tests
make test-e2e          # End-to-end tests
make test-performance  # Performance tests

# Generate coverage report
make test-coverage
```

### Code Quality

```bash
# Run linter
make lint

# Check for vulnerabilities
make vulncheck

# Format code
make fmt

# Run go vet
make vet
```

### Available Make Targets

```bash
# Show all available targets
make help

# Test environment targets
make test-env-up        # Start test environment
make test-env-down      # Stop test environment
make test-env-status    # Check service status
make test-env-logs      # View service logs
make test-env-clean     # Clean test environment
make test-env-wait      # Wait for services to be ready
make test-integration   # Run integration tests
make test-e2e          # Run end-to-end tests
make test-performance  # Run performance tests
make generate-certs    # Generate self-signed certificates

# Helm targets
make helm-lint         # Lint Helm chart
make helm-template     # Render Helm chart templates (dry-run)
make helm-package      # Package Helm chart
```

## Docker

### Building the Image

```bash
# Build Docker image
make docker-build

# Check image size
make docker-size
```

### Running the Container

```bash
# Run with default configuration (no authentication)
make docker-run

# Run with custom ports (gRPC and metrics)
docker run --rm -p 50051:50051 -p 9090:9090 alexey/grpc-example:latest

# Run with mTLS authentication
docker run --rm -p 8080:50051 -p 9090:9090 \
  -v /path/to/certs:/certs:ro \
  -e AUTH_MODE=mtls \
  -e TLS_ENABLED=true \
  -e TLS_MODE=mutual \
  -e TLS_CERT_PATH=/certs/server.crt \
  -e TLS_KEY_PATH=/certs/server.key \
  -e TLS_CA_PATH=/certs/ca.crt \
  -e TLS_CLIENT_AUTH=RequireAndVerifyClientCert \
  alexey/grpc-example:latest

# Run with OIDC authentication
docker run --rm -p 8080:50051 -p 9090:9090 \
  -e AUTH_MODE=oidc \
  -e OIDC_ENABLED=true \
  -e OIDC_ISSUER_URL=https://keycloak.example.com/realms/grpc \
  -e OIDC_CLIENT_ID=grpc-server \
  -e OIDC_CLIENT_SECRET=grpc-server-secret \
  alexey/grpc-example:latest
```

### Docker Compose Example

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  grpc-server:
    image: alexey/grpc-example:latest
    ports:
      - "50051:50051"
      - "9090:9090"
    environment:
      - GRPC_PORT=50051
      - METRICS_PORT=9090
      - LOG_LEVEL=info
      - SHUTDOWN_TIMEOUT=30s
      - AUTH_MODE=both
      - TLS_ENABLED=true
      - TLS_MODE=mutual
      - OIDC_ENABLED=true
      - OIDC_ISSUER_URL=https://keycloak.example.com/realms/grpc
      - OIDC_CLIENT_ID=grpc-server
      - OIDC_CLIENT_SECRET=grpc-server-secret
    volumes:
      - ./certs:/certs:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "grpcurl", "-plaintext", "localhost:50051", "list"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

Run with:

```bash
docker-compose up -d
```

## Kubernetes Deployment

The project includes a comprehensive Helm chart for deploying the gRPC server to Kubernetes with support for all authentication modes, TLS, observability, and production-ready features.

### Quick Start

```bash
# Install with default configuration (no authentication)
helm install my-grpc-server ./helm/grpc-server

# Install with custom values
helm install my-grpc-server ./helm/grpc-server \
  --set replicaCount=3 \
  --set metrics.serviceMonitor.enabled=true
```

### Configuration Examples

#### Basic Deployment with Metrics

```bash
helm install grpc-server ./helm/grpc-server \
  --set metrics.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --set service.type=LoadBalancer
```

#### mTLS with Vault PKI

```bash
# Create Vault token secret
kubectl create secret generic vault-token --from-literal=token=hvs.CAESIJ...

# Install with Vault PKI
helm install grpc-server ./helm/grpc-server \
  --set auth.mode=mtls \
  --set tls.enabled=true \
  --set tls.mode=mtls \
  --set vault.enabled=true \
  --set vault.addr=https://vault.example.com:8200 \
  --set vault.tokenSecretName=vault-token \
  --set vault.pkiRole=grpc-server
```

#### OIDC Authentication

```bash
# Create OIDC client secret
kubectl create secret generic oidc-secret --from-literal=client-secret=your-secret

# Install with OIDC
helm install grpc-server ./helm/grpc-server \
  --set auth.mode=oidc \
  --set oidc.enabled=true \
  --set oidc.issuerURL=https://keycloak.example.com/realms/grpc \
  --set oidc.clientID=grpc-server \
  --set oidc.clientSecretName=oidc-secret
```

#### OpenTelemetry (Traces and Metrics)

```bash
# otel.endpoint is host:port (no scheme); 4318 is the default OTLP/HTTP port
helm install grpc-server ./helm/grpc-server \
  --set otel.enabled=true \
  --set otel.endpoint=otel-collector:4318 \
  --set otel.serviceName=grpc-server
```

#### Production Configuration

```bash
helm install grpc-server ./helm/grpc-server \
  --set replicaCount=3 \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=10 \
  --set podDisruptionBudget.enabled=true \
  --set podDisruptionBudget.minAvailable=2 \
  --set metrics.serviceMonitor.enabled=true \
  --set resources.limits.cpu=1000m \
  --set resources.limits.memory=256Mi \
  --set service.type=LoadBalancer
```

### Values Override Example

Create a `values.yaml` file:

```yaml
# values.yaml
replicaCount: 3

image:
  repository: alexey/grpc-example
  tag: "v1.0.0"

server:
  logLevel: info
  enableReflection: true

auth:
  mode: both  # mTLS + OIDC

tls:
  enabled: true
  mode: mtls

vault:
  enabled: true
  addr: https://vault.example.com:8200
  tokenSecretName: vault-token
  pkiRole: grpc-server

oidc:
  enabled: true
  issuerURL: https://keycloak.example.com/realms/grpc
  clientID: grpc-server
  clientSecretName: oidc-secret

otel:
  enabled: true
  endpoint: otel-collector:4318  # host:port, no scheme (OTLP/HTTP)
  serviceName: grpc-server

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

podDisruptionBudget:
  enabled: true
  minAvailable: 2

resources:
  limits:
    cpu: 1000m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 64Mi
```

Install with custom values:

```bash
helm install grpc-server ./helm/grpc-server -f values.yaml
```

### Helm Chart Documentation

For complete Helm chart documentation, configuration options, and examples, see:
- [Helm Chart README](helm/grpc-server/README.md)

### Testing the Deployment

```bash
# Run Helm tests
helm test grpc-server

# Port forward to test locally
kubectl port-forward svc/grpc-server 50051:50051 9090:9090

# Test gRPC endpoint
grpcurl -plaintext -d '{"message": "Hello Kubernetes!"}' \
  localhost:50051 api.v1.TestService/Unary

# Check metrics
curl http://localhost:9090/metrics
```

## CI/CD

### CI Workflow

The CI workflow (`.github/workflows/ci.yml`) runs on pull requests and version tags and includes:

The pipeline pins its toolchain to **Go 1.26.4** and **golangci-lint v2.12.2** (matching the
`Makefile` and `go.mod`).

1. **Parallel Stage:**
   - Code linting with golangci-lint v2.12.2
   - Vulnerability scanning with govulncheck (build is kept clean of known vulnerabilities)
   - Unit tests with coverage reporting
   - Functional tests with coverage reporting
   - Helm chart linting and dry-run validation
   - Integration tests with test environment
   - End-to-end authentication tests

2. **Sequential Stage:**
   - SonarCloud code analysis
   - Binary build verification
   - Docker image build test

### Release Workflow

The CI workflow also handles releases when triggered by version tags and includes:

1. **Quality Checks:** Same as PR workflow
2. **Build & Release:**
   - Multi-platform binary builds
   - GitHub release creation with artifacts
   - Checksum generation
3. **Docker:**
   - Multi-architecture Docker builds (amd64, arm64)
   - Push to GitHub Container Registry (ghcr.io) with semantic versioning
   - SBOM generation (SPDX)
4. **Helm:**
   - Helm chart packaging with version updates
   - Chart artifact upload to GitHub release
5. **Security:**
   - Trivy vulnerability scanning
   - SARIF report upload to GitHub Security

### Required Secrets

Configure these secrets in your GitHub repository:

| Secret | Description | Required For |
|--------|-------------|--------------|
| `CODECOV_TOKEN` | Codecov upload token | Coverage reporting |
| `SONAR_TOKEN` | SonarCloud authentication | Code analysis |

Docker images are pushed to the GitHub Container Registry (ghcr.io) using the built-in
`GITHUB_TOKEN`; no additional registry secrets are required.

### Triggering a Release

```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0

# The release workflow will automatically:
# 1. Run all quality checks
# 2. Build binaries for multiple platforms
# 3. Create a GitHub release
# 4. Build and push Docker images
# 5. Run security scans
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass (`make test`)
6. Run linting (`make lint`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/vyrodovalexey/grpc-example/issues) page
2. Create a new issue with detailed information
3. Include logs, configuration, and steps to reproduce

## Acknowledgments

- [gRPC](https://grpc.io/) - High performance RPC framework
- [Protocol Buffers](https://developers.google.com/protocol-buffers) - Language-neutral data serialization
- [Zap](https://github.com/uber-go/zap) - Structured logging library
- [golangci-lint](https://golangci-lint.run/) - Go linters aggregator
- [HashiCorp Vault](https://www.vaultproject.io/) - Secrets and certificate management
- [Keycloak](https://www.keycloak.org/) - Identity and access management