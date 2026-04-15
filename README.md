# Network Policy Generator

![Top Language](https://img.shields.io/github/languages/top/somaz94/network-policy-generator?color=green&logo=go&logoColor=b)
![Version](https://img.shields.io/github/v/tag/somaz94/network-policy-generator?label=version&logo=kubernetes&logoColor=white)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/somaz94/network-policy-generator)](https://goreportcard.com/report/github.com/somaz94/network-policy-generator)
![Docker Pulls](https://img.shields.io/docker/pulls/somaz940/network-policy-generator?logo=docker&logoColor=white)
![GitHub Release](https://img.shields.io/github/release/somaz94/network-policy-generator?logo=github)
![GitHub Stars](https://img.shields.io/github/stars/somaz94/network-policy-generator?style=social)

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
- Supporting multiple CNI backends via `policyEngine` field (`kubernetes`, `cilium`, `calico`)
- Providing built-in policy templates for common workload types (web-app, database, monitoring, etc.)
- Generating namespace and rule suggestions from observed traffic during learning mode

### Key Features

![Pod Selector](https://img.shields.io/badge/Pod_Label_Selector-blue?logo=kubernetes&logoColor=white)
![CIDR Rules](https://img.shields.io/badge/CIDR_Rules-blue?logo=kubernetes&logoColor=white)
![Named Port](https://img.shields.io/badge/Named_Port-blue?logo=kubernetes&logoColor=white)
![Dry Run](https://img.shields.io/badge/Dry_Run-green?logo=kubernetes&logoColor=white)
![Policy Diff](https://img.shields.io/badge/Policy_Diff/Audit-green?logo=kubernetes&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes_NetworkPolicy-326CE5?logo=kubernetes&logoColor=white)
![Cilium](https://img.shields.io/badge/Cilium_NetworkPolicy-F8C517?logo=cilium&logoColor=black)
![Calico](https://img.shields.io/badge/Calico_NetworkPolicy-FF6D00?logo=kubernetes&logoColor=white)
![Policy Templates](https://img.shields.io/badge/Policy_Templates-teal?logo=kubernetes&logoColor=white)
![Learning Mode](https://img.shields.io/badge/Learning_Mode-orange?logo=kubernetes&logoColor=white)
![Event Recording](https://img.shields.io/badge/Event_Recording-purple?logo=kubernetes&logoColor=white)
![Prometheus Metrics](https://img.shields.io/badge/Prometheus_Metrics-E6522C?logo=prometheus&logoColor=white)
![Webhook Validation](https://img.shields.io/badge/Webhook_Validation-red?logo=kubernetes&logoColor=white)

- **Pod Label Selector** — Target specific pods by label instead of entire namespaces
- **CIDR-based Rules** — Define ingress/egress rules for external IP ranges (e.g., databases, external APIs)
- **Named Port Support** — Use service port names (`http`, `grpc`) instead of numeric ports
- **Dry Run Mode** — Preview generated policies in status without applying them to the cluster
- **Policy Diff/Audit** — Track policy changes (Created/Updated) in status for audit trails
- **Event Recording** — Emit Kubernetes Events on policy apply, delete, mode transition, and errors
- **Prometheus Metrics** — Custom metrics for reconcile count, duration, active generators, and policy operations
- **Webhook Validation** — Admission webhook for CRD validation (enable with `--enable-webhooks` flag, requires cert-manager)

<br/>

## Installation

<br/>

### Prerequisites
- Kubernetes v1.16+
- kubectl v1.11.3+
- For Cilium policies: Cilium CNI installed on the cluster
- For Calico policies: Calico CNI installed on the cluster

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
  --set image.tag=v0.3.0 \
  --set crds.cleanup=false \
  --namespace npg-system --create-namespace
```

For full Helm chart options, see [Helm README](docs/HELM.md).

<br/>

### Option 2: kubectl apply (Quick Install)

```bash
kubectl apply -f https://raw.githubusercontent.com/somaz94/network-policy-generator/main/dist/install.yaml
```

<br/>

### Option 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/somaz94/network-policy-generator.git
cd network-policy-generator

# Install CRDs
make install

# Deploy the controller
make deploy IMG=somaz940/network-policy-generator:v0.3.0
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
- `security_v1_networkpolicygenerator-pod-selector.yaml`: Pod label selector example
- `security_v1_networkpolicygenerator-cidr-rules.yaml`: CIDR-based egress/ingress rules
- `security_v1_networkpolicygenerator-named-port.yaml`: Named port (`http`, `grpc`) example
- `security_v1_networkpolicygenerator-dry-run.yaml`: Dry run mode (preview without applying)
- `security_v1_networkpolicygenerator-full-features.yaml`: All features combined
- `security_v1_networkpolicygenerator-calico-deny.yaml`: Calico deny policy
- `security_v1_networkpolicygenerator-calico-allow.yaml`: Calico allow policy
- `security_v1_networkpolicygenerator-template-web-app.yaml`: Web-app policy template
- `security_v1_networkpolicygenerator-template-database.yaml`: Database policy template
- `security_v1_networkpolicygenerator-template-backend-api.yaml`: Backend API policy template
- `security_v1_networkpolicygenerator-template-monitoring.yaml`: Monitoring policy template
- `security_v1_networkpolicygenerator-cilium-deny.yaml`: Cilium deny policy
- `security_v1_networkpolicygenerator-cilium-allow.yaml`: Cilium allow policy
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

### 5. Pod Label Selector
Target specific pods by label instead of applying to the entire namespace:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: pod-selector-example
spec:
  mode: "enforcing"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
    podSelector:
      app: nginx
      tier: frontend
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
```

<br/>

### 6. CIDR-based Rules
Define egress/ingress rules for external IP ranges:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: cidr-rules-example
spec:
  mode: "enforcing"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
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

<br/>

### 7. Named Port Support
Use service port names instead of numeric ports:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: named-port-example
spec:
  mode: "enforcing"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
  globalRules:
    - type: "allow"
      namedPort: "http"
      protocol: TCP
      direction: "ingress"
    - type: "allow"
      namedPort: "grpc"
      protocol: TCP
      direction: "egress"
```

<br/>

### 8. Dry Run Mode
Preview generated policies without applying them:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: dry-run-example
spec:
  mode: "enforcing"
  dryRun: true
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
```

Generated policies are stored in `.status.generatedPolicies` as JSON. No NetworkPolicy resources are created.

<br/>

### 9. Calico NetworkPolicy
Generate Calico-native `crd.projectcalico.org/v1` NetworkPolicy resources:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: calico-deny-example
spec:
  mode: "enforcing"
  policyEngine: "calico"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
    podSelector:
      app: web
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
```

Calico policies use selector-based syntax (`app == 'web'`), namespace selectors via `projectcalico.org/name`, and include automatic DNS egress allow rules.

<br/>

### 10. Policy Templates
Use built-in templates for common workload types instead of writing rules from scratch:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: template-web-app-example
spec:
  mode: "enforcing"
  templateName: "web-app"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
```

Available templates:
| Template | Description |
|----------|-------------|
| `zero-trust` | Deny all traffic, allow only DNS egress |
| `web-app` | Allow HTTP/HTTPS ingress, DNS and HTTPS egress |
| `backend-api` | Allow API ports (8080, 8443, 9090) ingress, HTTPS egress |
| `database` | Allow DB ports (3306, 5432, 6379, 27017) ingress, DNS-only egress |
| `monitoring` | Allow Prometheus scraping (9090, 9100), HTTPS egress |

Templates are merged with user-defined `globalRules` (user rules take precedence over template rules).

<br/>

### 11. Learning Mode with Suggestions
Learning mode now generates namespace and rule suggestions based on observed traffic:

```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: traffic-learner-improved
spec:
  mode: "learning"
  duration: "5m"
  policy:
    type: "deny"
```

After the learning period, check suggestions:

```bash
# View suggested namespaces from observed traffic
kubectl get networkpolicygenerator traffic-learner-improved -o jsonpath='{.status.suggestedNamespaces}'

# View suggested port/protocol rules with observation counts
kubectl get networkpolicygenerator traffic-learner-improved -o jsonpath='{.status.suggestedRules}'
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

# Integration tests (auto-detects CNI and runs matching tests)
make test-integration                      # Auto-detect CNI
make test-integration ENGINE=kubernetes    # Kubernetes only
make test-integration ENGINE=cilium        # Cilium only
make test-integration ENGINE=calico        # Calico only
make test-integration ENGINE=all           # Force all engines

# Helm chart tests (lint, install, upgrade, policy tests, uninstall)
make test-helm                             # Auto-detect CNI
make test-helm ENGINE=kubernetes           # Kubernetes only
make test-helm ENGINE=cilium               # Cilium only
make test-helm ENGINE=calico               # Calico only
make test-helm ENGINE=all                  # Force all engines
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

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

