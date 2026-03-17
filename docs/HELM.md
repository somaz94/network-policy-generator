# Network Policy Generator Helm Chart

<br/>

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- For Cilium policies: Cilium CNI installed on the cluster
- For Calico policies: Calico CNI installed on the cluster

<br/>

## Installation

<br/>

### From Helm Repository

```bash
helm repo add network-policy-generator https://somaz94.github.io/network-policy-generator/helm-repo
helm repo update
helm install npg network-policy-generator/network-policy-generator
```

<br/>

### From Local

```bash
helm install npg ./helm/network-policy-generator
```

<br/>

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace` | Namespace for the controller | `network-policy-generator-system` |
| `image.repository` | Controller image repository | `somaz940/network-policy-generator` |
| `image.tag` | Controller image tag | `v0.2.0` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name | `network-policy-generator-controller-manager` |
| `podSecurityContext.runAsNonRoot` | Run pod as non-root user | `true` |
| `securityContext.allowPrivilegeEscalation` | Disallow privilege escalation | `false` |
| `securityContext.capabilities.drop` | Drop all Linux capabilities | `["ALL"]` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `controller.metricsBindAddress` | Metrics bind address | `:8443` |
| `controller.healthProbeBindAddress` | Health probe bind address | `:8081` |
| `controller.leaderElect` | Enable leader election | `true` |
| `service.type` | Metrics service type | `ClusterIP` |
| `service.port` | Metrics service port | `8443` |
| `probes.liveness.initialDelaySeconds` | Liveness probe initial delay | `15` |
| `probes.liveness.periodSeconds` | Liveness probe period | `20` |
| `probes.liveness.port` | Liveness probe port | `8081` |
| `probes.readiness.initialDelaySeconds` | Readiness probe initial delay | `5` |
| `probes.readiness.periodSeconds` | Readiness probe period | `10` |
| `probes.readiness.port` | Readiness probe port | `8081` |
| `rbac.enabled` | Create RBAC resources | `true` |
| `crds.enabled` | Install CRDs | `true` |
| `crds.cleanup` | Cleanup CRDs on uninstall | `true` |
| `metrics.enabled` | Enable metrics service | `true` |
| `metrics.port` | Metrics port | `8443` |

> **Note**: Admission webhooks can be enabled with the `--enable-webhooks` controller flag (requires cert-manager). This is a controller argument, not a Helm value.

<br/>

## Usage

After installation, create a NetworkPolicyGenerator resource:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: example
  namespace: default
spec:
  mode: "enforcing"
  policyEngine: "kubernetes"  # or "cilium" or "calico"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
  globalRules:
    - type: "allow"
      port: 53
      protocol: UDP
      direction: "egress"
```

<br/>

## Advanced Features

After installation, you can use these additional CRD fields:

### Pod Label Selector

```yaml
spec:
  podSelector:
    app: nginx
    tier: frontend
```

### CIDR-based Rules

```yaml
spec:
  cidrRules:
    - cidr: "10.0.0.0/8"
      direction: "egress"
      protocol: TCP
      port: 5432
    - cidr: "192.168.1.0/24"
      except:
        - "192.168.1.100/32"
      direction: "ingress"
      protocol: TCP
      port: 443
```

### Named Port

```yaml
spec:
  globalRules:
    - type: "allow"
      namedPort: "http"
      protocol: TCP
      direction: "ingress"
```

### Dry Run Mode

```yaml
spec:
  dryRun: true
```

Generated policies are stored in `.status.generatedPolicies` without being applied. Policy changes are tracked in `.status.policyDiff`.

<br/>

## Upgrade

```bash
helm repo update
helm upgrade npg network-policy-generator/network-policy-generator
```

<br/>

## Custom Values Example

Create a `custom-values.yaml`:

```yaml
image:
  tag: v0.2.0

namespace: custom-namespace

resources:
  limits:
    cpu: 1000m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

controller:
  leaderElect: true

crds:
  cleanup: false  # Keep CRDs on uninstall
```

Install with custom values:

```bash
helm install npg network-policy-generator/network-policy-generator -f custom-values.yaml
```

<br/>

## Uninstall

```bash
helm uninstall npg
```
