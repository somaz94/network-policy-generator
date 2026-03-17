# Network Policy Generator Helm Chart

<br/>

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- For Cilium policies: Cilium CNI installed on the cluster

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
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `controller.leaderElect` | Enable leader election | `true` |
| `rbac.enabled` | Create RBAC resources | `true` |
| `crds.enabled` | Install CRDs | `true` |
| `crds.cleanup` | Cleanup CRDs on uninstall | `true` |
| `metrics.enabled` | Enable metrics service | `true` |
| `metrics.port` | Metrics port | `8443` |

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
  policyEngine: "kubernetes"  # or "cilium"
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
