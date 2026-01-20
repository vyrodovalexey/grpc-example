# gRPC Test Server

[![CI](https://github.com/alexey/grpc-example/actions/workflows/pr.yml/badge.svg)](https://github.com/alexey/grpc-example/actions/workflows/pr.yml)
[![Coverage](https://codecov.io/gh/alexey/grpc-example/branch/main/graph/badge.svg)](https://codecov.io/gh/alexey/grpc-example)
[![Go Version](https://img.shields.io/badge/go-1.24-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A comprehensive gRPC test server implementation in Go, designed for testing and development purposes. This server provides three different types of gRPC endpoints to demonstrate various communication patterns.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Development](#development)
- [Docker](#docker)
- [CI/CD](#cicd)
- [License](#license)

## Overview

This project implements a gRPC test server with three endpoint types:

- **Unary RPC** - Simple request-response pattern
- **Server Streaming RPC** - Server sends multiple responses for a single request
- **Bidirectional Streaming RPC** - Both client and server can send multiple messages

The server is built with production-ready features including structured logging, graceful shutdown, comprehensive testing, and Docker support.

## Features

- ✅ Three gRPC endpoint types (Unary, Server Streaming, Bidirectional Streaming)
- ✅ Structured JSON logging with configurable levels
- ✅ Graceful shutdown with configurable timeout
- ✅ Comprehensive unit and functional tests
- ✅ Docker support with multi-stage builds
- ✅ CI/CD pipelines with GitHub Actions
- ✅ Code quality checks (linting, vulnerability scanning)
- ✅ Coverage reporting with Codecov
- ✅ SonarCloud integration for code analysis
- ✅ Automated releases with GitHub Releases

## Prerequisites

- **Go 1.24+** - [Download](https://golang.org/dl/)
- **Protocol Buffers Compiler (protoc)** - [Installation Guide](https://grpc.io/docs/protoc-installation/)
- **Docker** (optional) - [Download](https://www.docker.com/get-started)

### Install Required Tools

```bash
# Install development tools
make tools

# Or install manually
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
go install golang.org/x/vuln/cmd/govulncheck@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
go install golang.org/x/tools/cmd/goimports@latest
```

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/alexey/grpc-example.git
cd grpc-example
```

### 2. Build and Run

```bash
# Generate protobuf code, run tests, and build
make all

# Run the server
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

## Configuration

The server can be configured using environment variables:

| Variable | Description | Default | Valid Values |
|----------|-------------|---------|--------------|
| `GRPC_PORT` | gRPC server port | `50051` | `1-65535` |
| `METRICS_PORT` | Metrics server port | `9090` | `1-65535` |
| `LOG_LEVEL` | Logging level | `info` | `debug`, `info`, `warn`, `error` |
| `SHUTDOWN_TIMEOUT` | Graceful shutdown timeout | `30s` | Duration string (e.g., `30s`, `1m`) |

### Example Configuration

```bash
export GRPC_PORT=8080
export LOG_LEVEL=debug
export SHUTDOWN_TIMEOUT=60s
./bin/grpc-server
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
│   ├── config/           # Configuration management
│   ├── server/           # gRPC server implementation
│   └── service/          # Business logic
├── pkg/api/v1/           # Generated protobuf code
├── test/
│   ├── functional/       # End-to-end tests
│   └── cases/           # Test case definitions
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

# Run only unit tests
make test-unit

# Run only functional tests
make test-functional

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
# Run with default configuration
make docker-run

# Run with custom configuration
docker run --rm -p 8080:50051 \
  -e GRPC_PORT=50051 \
  -e LOG_LEVEL=debug \
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

## CI/CD

### Pull Request Workflow

The PR workflow (`.github/workflows/pr.yml`) runs on every pull request and includes:

1. **Parallel Stage:**
   - Code linting with golangci-lint
   - Vulnerability scanning with govulncheck
   - Unit tests with coverage reporting
   - Functional tests with coverage reporting

2. **Sequential Stage:**
   - SonarCloud code analysis
   - Binary build verification
   - Docker image build test

### Release Workflow

The release workflow (`.github/workflows/release.yml`) runs on version tags and includes:

1. **Quality Checks:** Same as PR workflow
2. **Build & Release:**
   - Multi-platform binary builds
   - GitHub release creation with artifacts
   - Checksum generation
3. **Docker:**
   - Multi-architecture Docker builds (amd64, arm64)
   - Push to Docker Hub with semantic versioning
4. **Security:**
   - Trivy vulnerability scanning
   - SARIF report upload to GitHub Security

### Required Secrets

Configure these secrets in your GitHub repository:

| Secret | Description | Required For |
|--------|-------------|--------------|
| `CODECOV_TOKEN` | Codecov upload token | Coverage reporting |
| `SONAR_TOKEN` | SonarCloud authentication | Code analysis |
| `DOCKERHUB_USERNAME` | Docker Hub username | Docker image push |
| `DOCKERHUB_TOKEN` | Docker Hub access token | Docker image push |

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

1. Check the [Issues](https://github.com/alexey/grpc-example/issues) page
2. Create a new issue with detailed information
3. Include logs, configuration, and steps to reproduce

## Acknowledgments

- [gRPC](https://grpc.io/) - High performance RPC framework
- [Protocol Buffers](https://developers.google.com/protocol-buffers) - Language-neutral data serialization
- [Zap](https://github.com/uber-go/zap) - Structured logging library
- [golangci-lint](https://golangci-lint.run/) - Go linters aggregator