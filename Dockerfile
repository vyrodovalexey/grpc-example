# syntax=docker/dockerfile:1

# ================================
# Build Stage
# ================================
FROM golang:1.24-alpine AS builder

# Build arguments
ARG VERSION=dev
ARG BUILD_TIME=unknown
ARG GIT_COMMIT=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
    -o /build/grpc-server \
    ./cmd/server

# ================================
# Runtime Stage
# ================================
FROM gcr.io/distroless/static-debian12:nonroot

# OCI Labels
LABEL org.opencontainers.image.title="gRPC Test Server" \
      org.opencontainers.image.description="A gRPC test server for testing and development" \
      org.opencontainers.image.vendor="alexey" \
      org.opencontainers.image.source="https://github.com/alexey/grpc-example" \
      org.opencontainers.image.licenses="MIT"

# Copy binary from builder
COPY --from=builder /build/grpc-server /grpc-server

# Copy timezone data and CA certificates
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set environment variables
ENV GRPC_HOST=0.0.0.0 \
    GRPC_PORT=50051 \
    LOG_LEVEL=info \
    SHUTDOWN_TIMEOUT=30s

# Expose gRPC port
EXPOSE 50051

# Use non-root user (provided by distroless:nonroot)
USER nonroot:nonroot

# Health check using grpc_health_probe would require additional binary
# For distroless, we rely on Kubernetes probes or external health checks

# Run the server
ENTRYPOINT ["/grpc-server"]
