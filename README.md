# Network Policy Generator

![Top Language](https://img.shields.io/github/languages/top/somaz94/network-policy-generator?color=green&logo=go&logoColor=b)
![Version](https://img.shields.io/github/v/tag/somaz94/network-policy-generator?label=version&logo=kubernetes&logoColor=white)

A Kubernetes controller that automatically generates and manages Kubernetes Network Policies based on observed traffic patterns and user-defined rules.

<br/>

## Description

The Network Policy Generator is a Kubernetes operator that simplifies the creation and management of Network Policies by providing two main operational modes:

- **Learning Mode**: Analyzes actual network traffic patterns within your cluster for a specified duration
- **Enforcing Mode**: Automatically generates and applies Network Policies based on learned patterns or predefined rules

This tool helps security teams and cluster administrators implement network segmentation more effectively by:
- Reducing manual Network Policy creation overhead
- Providing data-driven policy recommendations based on real traffic
- Supporting both permissive (allow-based) and restrictive (deny-based) policy approaches
- Enabling gradual transition from learning to enforcement phases
- Supporting multiple CNI backends via `policyEngine` field (`kubernetes`, `cilium`)

<br/>

## Installation

<br/>

### Prerequisites
- Kubernetes v1.16+
- kubectl v1.11.3+
- For Cilium policies: Cilium CNI installed on the cluster

<br/>

### Option 1: Helm (Recommended)

```bash
# Add the Helm repository
helm repo add network-policy-generator https://somaz94.github.io/network-policy-generator/helm-repo
helm repo update

# Install with default values
helm install npg network-policy-generator/network-policy-generator

# Or install with custom values
helm install npg network-policy-generator/network-policy-generator \
  --set image.tag=v0.1.1 \
  --set crds.cleanup=false \
  --namespace npg-system --create-namespace
```

For full Helm chart options, see [Helm README](docs/HELM.md).

<br/>

### Option 2: kubectl apply (Quick Install)

```bash
kubectl apply -f https://raw.githubusercontent.com/somaz94/network-policy-generator/main/dist/install.yaml
```

> **NOTE**: Generate `dist/install.yaml` first if it doesn't exist:
> ```bash
> make build-installer IMG=somaz940/network-policy-generator:v0.1.1
> ```

<br/>

### Option 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/somaz94/network-policy-generator.git
cd network-policy-generator

# Install CRDs
make install

# Deploy the controller
make deploy IMG=somaz940/network-policy-generator:v0.1.1
```

<br/>

### Verify Installation

```bash
# Check the controller is running
kubectl get pods -n network-policy-generator-system

# Check CRDs are installed
kubectl get crd networkpolicygenerators.security.policy.io
```

<br/>

## Quick Start

After installation, create a `NetworkPolicyGenerator` resource:

```bash
# Apply a sample policy
kubectl apply -f config/samples/security_v1_networkpolicygenerator-deny.yaml

# Check the status
kubectl get networkpolicygenerator

# View generated NetworkPolicies
kubectl get networkpolicy -A
```

Available sample configurations:
- `security_v1_networkpolicygenerator-allow.yaml`: Allow-based policy example
- `security_v1_networkpolicygenerator-deny.yaml`: Deny-based policy example
- `security_v1_networkpolicygenerator.yaml`: Learning mode example
- `test-policy.yaml`: Namespace-specific policy examples
- `test.yaml`: Test pods and services for validation

<br/>

### Uninstall

```bash
# Helm
helm uninstall npg

# kubectl
kubectl delete -f https://raw.githubusercontent.com/somaz94/network-policy-generator/main/dist/install.yaml

# From source
make undeploy
make uninstall
```

<br/>

## Usage Examples

<br/>

### 1. Allow-based Policy (Default Deny)
Creates a policy that denies all traffic by default, only allowing traffic from specified namespaces:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: test-policy-generator-allow
spec:
  mode: "enforcing"
  policy:
    type: "allow"     # Default deny, explicit allow
    deniedNamespaces: # Namespaces to deny access from
      - "test-ns1"
      - "test-ns2"
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
    - type: "allow"
      port: 443
      protocol: TCP
      direction: "egress"
```

<br/>

### 2. Deny-based Policy (Default Allow)
Creates a policy that allows all traffic by default, only denying traffic from specified namespaces:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: test-policy-generator-deny
spec:
  mode: "enforcing"
  policy:
    type: "deny"      # Default allow, explicit deny
    allowedNamespaces: # Only these namespaces are allowed
      - "test-ns1"
      - "test-ns2"
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
    - type: "allow"
      port: 443
      protocol: TCP
      direction: "egress"
```

<br/>

### 3. Learning Mode Example
Analyzes traffic patterns for a specified duration before generating policies:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: traffic-learner
spec:
  mode: "learning"
  duration: "1m"      # Analyze traffic for 1 minute (use longer durations in production)
  policy:
    type: "deny"
    allowedNamespaces:
      - "test-ns1"
      - "test-ns2"
    deniedNamespaces:
      - "test-ns3"
      - "test-ns4"
```

<br/>

### 4. Namespace-specific Policy
Apply different policies to different namespaces:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: test-policy-generator-deny
  namespace: test-ns1
spec:
  mode: "enforcing"
  policy:
    type: "deny"
    allowedNamespaces:
      - "test-ns3"  # Only test-ns3 can access test-ns1
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
```

<br/>

### Monitoring the Generator Status
```sh
# View all NetworkPolicyGenerator resources
kubectl get networkpolicygenerator

# Get detailed information about a specific generator
kubectl describe networkpolicygenerator <name>

# Check the status and observed traffic (in learning mode)
kubectl get networkpolicygenerator <name> -o yaml
```

<br/>

## Testing

```sh
# Unit tests
make test

# Integration tests (deploy to real cluster and test all sample policies)
make test-integration                      # All engines
make test-integration ENGINE=kubernetes    # Kubernetes only
make test-integration ENGINE=cilium        # Cilium only

# Helm chart tests (lint, install, upgrade, policy tests, uninstall)
make test-helm                             # All engines
make test-helm ENGINE=kubernetes           # Kubernetes only
make test-helm ENGINE=cilium               # Cilium only
```

For detailed manual test steps and sample descriptions, see [Test Guide](docs/TESTING.md).

<br/>

## Documentation

| Document | Description |
|----------|-------------|
| [Helm Chart](docs/HELM.md) | Helm chart installation, configuration, and values reference |
| [Testing Guide](docs/TESTING.md) | Unit, integration, Helm, and manual test instructions |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Version Bump](docs/VERSION_BUMP.md) | Checklist for releasing a new version |
| [Contributing](CONTRIBUTING.md) | How to contribute to this project |

<br/>

## Contributing

Issues and pull requests are welcome.

<br/>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

