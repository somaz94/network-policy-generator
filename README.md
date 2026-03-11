# Network Policy Generator

![Top Language](https://img.shields.io/github/languages/top/somaz94/network-policy-generator?color=green&logo=go&logoColor=b)
![helios-lb](https://img.shields.io/github/v/tag/somaz94/network-policy-generator?label=helios-lb&logo=kubernetes&logoColor=white)

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

## Getting Started

<br/>

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

<br/>

### To Deploy on the cluster

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/network-policy-generator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don't work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/network-policy-generator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/samples:

```sh
kubectl apply -k config/samples/
```

Available sample configurations:
- `security_v1_networkpolicygenerator-allow.yaml`: Allow-based policy example
- `security_v1_networkpolicygenerator-deny.yaml`: Deny-based policy example  
- `security_v1_networkpolicygenerator.yaml`: Learning mode example
- `test-policy.yaml`: Namespace-specific policy examples
- `test.yaml`: Test pods and services for validation

>**NOTE**: The samples include test namespaces (test-ns1, test-ns2, test-ns3) and sample pods for testing the network policies.

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

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

<br/>

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/network-policy-generator:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/network-policy-generator/<tag or branch>/dist/install.yaml
```

<br/>

## Testing with Sample Resources

The project includes test resources to validate network policy generation:

<br/>

### Test Environment Setup
```sh
# Create test namespaces
kubectl create namespace test-ns1
kubectl create namespace test-ns2  
kubectl create namespace test-ns3

# Apply test pods and services
kubectl apply -f config/samples/test.yaml

# Apply network policy generators
kubectl apply -f config/samples/security_v1_networkpolicygenerator-deny.yaml
kubectl apply -f config/samples/test-policy.yaml
```

<br/>

### Validate Network Policies
```sh
# Check generated network policies
kubectl get networkpolicy -A

# Test connectivity between pods
kubectl exec -n test-ns1 test-pod1 -- curl test-service2.test-ns2.svc.cluster.local
```

<br/>

## Contributing

Issues and pull requests are welcome.

<br/>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

