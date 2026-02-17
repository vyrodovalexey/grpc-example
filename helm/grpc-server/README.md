# gRPC Server Helm Chart

A Helm chart for deploying the gRPC test server with mTLS, OIDC, Vault PKI, and OpenTelemetry support.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- (Optional) Prometheus Operator for ServiceMonitor support
- (Optional) HashiCorp Vault for PKI certificate management
- (Optional) OIDC provider (e.g., Keycloak) for token-based authentication

## Installing the Chart

To install the chart with the release name `my-grpc-server`:

```bash
helm install my-grpc-server ./helm/grpc-server
```

## Uninstalling the Chart

To uninstall/delete the `my-grpc-server` deployment:

```bash
helm uninstall my-grpc-server
```

## Configuration

The following table lists the configurable parameters of the gRPC Server chart and their default values.

### General Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/vyrodovalexey/grpc-example` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |

### Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.port` | gRPC server port | `50051` |
| `server.metricsPort` | Metrics HTTP server port | `9090` |
| `server.logLevel` | Log level (debug, info, warn, error) | `info` |
| `server.shutdownTimeout` | Graceful shutdown timeout | `30s` |
| `server.enableReflection` | Enable gRPC reflection | `true` |

### TLS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tls.enabled` | Enable TLS | `false` |
| `tls.mode` | TLS mode (none, tls, mtls) | `none` |
| `tls.clientAuth` | Client auth mode (none, request, require) | `none` |
| `tls.existingSecret` | Name of existing TLS secret | `""` |

### Vault PKI Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vault.enabled` | Enable Vault PKI integration | `false` |
| `vault.addr` | Vault server address | `""` |
| `vault.tokenSecretName` | K8s secret containing Vault token | `""` |
| `vault.tokenSecretKey` | Key in secret for Vault token | `token` |
| `vault.pkiPath` | Vault PKI secrets engine path | `pki` |
| `vault.pkiRole` | Vault PKI role name | `grpc-server` |
| `vault.pkiTTL` | Certificate TTL | `24h` |

### Authentication Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.mode` | Auth mode (none, mtls, oidc, both) | `none` |

### OIDC Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `oidc.enabled` | Enable OIDC authentication | `false` |
| `oidc.issuerURL` | OIDC issuer URL | `""` |
| `oidc.clientID` | OIDC client ID | `""` |
| `oidc.clientSecretName` | K8s secret containing OIDC client secret | `""` |
| `oidc.clientSecretKey` | Key in secret for OIDC client secret | `client-secret` |
| `oidc.audience` | Expected audience in token | `""` |

### OpenTelemetry Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `otel.enabled` | Enable OpenTelemetry tracing | `false` |
| `otel.endpoint` | OTLP exporter endpoint | `""` |
| `otel.serviceName` | Service name for tracing | `""` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.grpcPort` | gRPC service port | `50051` |
| `service.metricsPort` | Metrics service port | `9090` |

### Metrics Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.serviceMonitor.enabled` | Create ServiceMonitor | `false` |
| `metrics.serviceMonitor.interval` | Scrape interval | `30s` |
| `metrics.serviceMonitor.labels` | Additional labels | `{}` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `64Mi` |

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `1` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |

### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PDB | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

## Examples

### Basic Installation

```bash
helm install my-grpc-server ./helm/grpc-server
```

### With TLS (using existing secret)

```bash
helm install my-grpc-server ./helm/grpc-server \
  --set tls.enabled=true \
  --set tls.mode=mtls \
  --set tls.existingSecret=my-tls-secret
```

### With Vault PKI

```bash
helm install my-grpc-server ./helm/grpc-server \
  --set tls.enabled=true \
  --set tls.mode=mtls \
  --set vault.enabled=true \
  --set vault.addr=https://vault.example.com:8200 \
  --set vault.tokenSecretName=vault-token
```

### With OIDC Authentication

```bash
helm install my-grpc-server ./helm/grpc-server \
  --set auth.mode=oidc \
  --set oidc.enabled=true \
  --set oidc.issuerURL=https://keycloak.example.com/realms/myrealm \
  --set oidc.clientID=grpc-server \
  --set oidc.clientSecretName=oidc-secret
```

### With OpenTelemetry

```bash
helm install my-grpc-server ./helm/grpc-server \
  --set otel.enabled=true \
  --set otel.endpoint=http://otel-collector:4317 \
  --set otel.serviceName=grpc-server
```

### Production Configuration

```bash
helm install my-grpc-server ./helm/grpc-server \
  --set replicaCount=3 \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=10 \
  --set podDisruptionBudget.enabled=true \
  --set podDisruptionBudget.minAvailable=2 \
  --set metrics.serviceMonitor.enabled=true \
  --set resources.limits.cpu=1000m \
  --set resources.limits.memory=256Mi
```

## Testing

Run the Helm tests:

```bash
helm test my-grpc-server
```

## License

MIT License - see [LICENSE](../../LICENSE) for details.
