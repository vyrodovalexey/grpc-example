# Performance Test Cases

## Overview
This document describes the performance and benchmark test cases for the gRPC Test Server. These tests measure authentication overhead, connection establishment costs, and throughput under various authentication modes.

## Test Categories

### 1. Benchmark Tests (`benchmark_test.go`)

#### Unary RPC Benchmarks

| Benchmark | Description | Metrics Measured |
|-----------|-------------|------------------|
| BenchmarkInsecure_UnaryRPC | Unary RPC without TLS or authentication | Latency, allocations per operation |
| BenchmarkTLS_UnaryRPC | Unary RPC with TLS (server-side only) | Latency, allocations per operation |
| BenchmarkMTLS_UnaryRPC | Unary RPC with mutual TLS authentication | Latency, allocations per operation |
| BenchmarkOIDC_UnaryRPC | Unary RPC with OIDC token authentication | Latency, allocations per operation |

#### Handshake Benchmarks

| Benchmark | Description | Metrics Measured |
|-----------|-------------|------------------|
| BenchmarkTLSHandshake | Raw TLS handshake (new connection per iteration) | Handshake latency, allocations |
| BenchmarkMTLSHandshake | Raw mTLS handshake (new connection per iteration) | Handshake latency, allocations |

#### Comparison Benchmarks

| Benchmark | Description | Metrics Measured |
|-----------|-------------|------------------|
| BenchmarkTokenValidationOverhead/no_auth | Baseline without authentication | Latency, allocations |
| BenchmarkTokenValidationOverhead/with_oidc | OIDC token validation overhead | Latency, allocations |
| BenchmarkAuthModes_Comparison/insecure | Insecure mode baseline | Latency |
| BenchmarkAuthModes_Comparison/tls | TLS overhead vs insecure | Latency |
| BenchmarkAuthModes_Comparison/mtls | mTLS overhead vs insecure | Latency |
| BenchmarkAuthModes_Comparison/oidc | OIDC overhead vs insecure | Latency |

#### Connection Establishment Benchmarks

| Benchmark | Description | Metrics Measured |
|-----------|-------------|------------------|
| BenchmarkNewConnection_Insecure | New connection + request (insecure) | Connection + request latency |
| BenchmarkNewConnection_MTLS | New connection + request (mTLS) | Connection + request latency |

### 2. Load Tests (`load_test.go`)

#### Concurrent Request Tests

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestPerformance_ConcurrentRequests_Insecure | 10 workers x 100 requests (insecure) | All 1000 requests succeed, 0 errors |
| TestPerformance_ConcurrentRequests_MTLS | 10 workers x 100 requests (mTLS) | All 1000 requests succeed, 0 errors |
| TestPerformance_ConcurrentRequests_OIDC | 10 workers x 100 requests (OIDC) | All 1000 requests succeed, 0 errors |

#### Connection Pooling Tests

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestPerformance_ConnectionPooling_MTLS | Compare shared vs new connections | Pooled connections significantly faster |

#### Token Caching Tests

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestPerformance_TokenCachingEffectiveness | Compare same token vs different tokens | Demonstrates caching behavior |

## Expected Baseline Performance

Based on Apple M1 Max (10 cores), these are typical baseline values:

### Unary RPC Latency (per operation)

| Auth Mode | Expected Latency | Expected Allocations |
|-----------|------------------|----------------------|
| Insecure | ~60-70 us | ~8.5 KB, ~147 allocs |
| TLS | ~65-75 us | ~8.6 KB, ~150 allocs |
| mTLS | ~65-75 us | ~9.5 KB, ~160 allocs |
| OIDC | ~65-75 us | ~11 KB, ~173 allocs |

### Handshake Latency (per connection)

| Handshake Type | Expected Latency | Expected Allocations |
|----------------|------------------|----------------------|
| TLS | ~600-700 us | ~108 KB, ~870 allocs |
| mTLS | ~750-850 us | ~128 KB, ~1100 allocs |

### Throughput (concurrent requests)

| Auth Mode | Expected Throughput |
|-----------|---------------------|
| Insecure | ~13,000+ req/s |
| mTLS | ~13,000+ req/s |
| OIDC | ~13,000+ req/s |

### Connection Pooling Impact

| Scenario | Expected Throughput |
|----------|---------------------|
| Pooled (shared connection) | ~1,500+ req/s |
| Unpooled (new connection per request) | ~500+ req/s |
| Expected Speedup | ~2.5-3x |

## Test Execution

### Run All Performance Tests
```bash
go test -v -tags=performance -run TestPerformance -timeout 5m ./test/performance/...
```

### Run All Benchmarks
```bash
go test -tags=performance -bench=. -benchtime=1s -run=^$ ./test/performance/...
```

### Run Specific Benchmark
```bash
# Run only mTLS benchmarks
go test -tags=performance -bench=MTLS -benchtime=1s -run=^$ ./test/performance/...

# Run only handshake benchmarks
go test -tags=performance -bench=Handshake -benchtime=1s -run=^$ ./test/performance/...

# Run auth mode comparison
go test -tags=performance -bench=AuthModes -benchtime=1s -run=^$ ./test/performance/...
```

### Run Benchmarks with Memory Profiling
```bash
go test -tags=performance -bench=. -benchmem -run=^$ ./test/performance/...
```

### Run Benchmarks with CPU Profiling
```bash
go test -tags=performance -bench=. -cpuprofile=cpu.prof -run=^$ ./test/performance/...
go tool pprof cpu.prof
```

### Run Benchmarks Multiple Times for Consistency
```bash
go test -tags=performance -bench=. -count=5 -run=^$ ./test/performance/...
```

### Compare Benchmark Results
```bash
# Install benchstat
go install golang.org/x/perf/cmd/benchstat@latest

# Run baseline
go test -tags=performance -bench=. -count=10 -run=^$ ./test/performance/... > baseline.txt

# Make changes, then run again
go test -tags=performance -bench=. -count=10 -run=^$ ./test/performance/... > new.txt

# Compare
benchstat baseline.txt new.txt
```

## Interpreting Results

### Benchmark Output Format
```
BenchmarkInsecure_UnaryRPC-10    18736    63350 ns/op    8565 B/op    147 allocs/op
```

| Field | Meaning |
|-------|---------|
| `-10` | Number of CPU cores used |
| `18736` | Number of iterations run |
| `63350 ns/op` | Nanoseconds per operation (latency) |
| `8565 B/op` | Bytes allocated per operation |
| `147 allocs/op` | Number of allocations per operation |

### Key Metrics to Monitor

1. **Latency (ns/op)**: Lower is better. Compare across auth modes to understand overhead.

2. **Allocations (B/op, allocs/op)**: Lower is better. High allocations can cause GC pressure.

3. **Throughput (req/s)**: Higher is better. Reported in load tests.

4. **Consistency**: Run multiple times. High variance indicates instability.

### Performance Regression Detection

Consider a regression if:
- Latency increases by more than 10%
- Allocations increase by more than 20%
- Throughput decreases by more than 10%

### Auth Mode Overhead Analysis

Expected overhead relative to insecure baseline:
- TLS: ~3-5% latency overhead (encryption)
- mTLS: ~5-10% latency overhead (client cert validation)
- OIDC: ~5-10% latency overhead (token validation)

Handshake overhead (one-time per connection):
- TLS: ~10x single RPC latency
- mTLS: ~12x single RPC latency

## Test Infrastructure

### Benchmark Helpers (`suite_test.go`)

| Helper | Description |
|--------|-------------|
| `benchCA` | Self-signed CA for generating test certificates |
| `newBenchCA()` | Creates a new CA for benchmark tests |
| `issueCert()` | Issues certificates signed by the CA |
| `insecureServer()` | Creates insecure gRPC server |
| `tlsServer()` | Creates TLS-only gRPC server |
| `mtlsServer()` | Creates mTLS gRPC server |
| `oidcServer()` | Creates OIDC-authenticated gRPC server |
| `insecureClient()` | Creates insecure gRPC client |
| `tlsClient()` | Creates TLS client |
| `mtlsClient()` | Creates mTLS client |
| `contextWithBearerToken()` | Adds bearer token to context |

### Mock OIDC Components

| Component | Description |
|-----------|-------------|
| `benchTokenVerifier` | Mock token verifier that always succeeds |
| `benchProvider` | Mock OIDC provider with `Verifier()` and `Healthy()` methods |

### Test Service

| Component | Description |
|-----------|-------------|
| `benchTestService` | Minimal service implementation for benchmarks |
| `Unary()` | Echoes message with timestamp |

## Best Practices

### Before Running Benchmarks

1. **Close other applications**: Reduce CPU/memory contention
2. **Disable power saving**: Ensure consistent CPU frequency
3. **Run multiple times**: Use `-count=5` or higher
4. **Warm up**: Benchmarks include warmup phase (10 iterations)

### Benchmark Design Patterns

1. **Use `b.ResetTimer()`**: Reset after setup to exclude setup time
2. **Use `b.ReportAllocs()`**: Track memory allocations
3. **Use `b.Loop()`**: Go 1.24+ loop pattern for accurate timing
4. **Include warmup**: 10 iterations before `b.ResetTimer()`
5. **Proper cleanup**: Use `defer cleanup()` for server shutdown

### Load Test Design Patterns

1. **Use `t.Parallel()`**: Run independent tests concurrently
2. **Use atomic counters**: Thread-safe success/error counting
3. **Use `sync.WaitGroup`**: Wait for all workers to complete
4. **Set reasonable timeouts**: 10s per request in load tests
5. **Log throughput**: Report req/s for comparison

## Test Tags

- `performance` - All performance and benchmark tests

## Dependencies

These tests are self-contained and do not require:
- Docker or docker-compose
- External OIDC provider
- External certificate authority
- Network access

All certificates and tokens are generated in-memory during test execution.
