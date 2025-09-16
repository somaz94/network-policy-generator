# Network Policy Generator

![Top Language](https://img.shields.io/github/languages/top/somaz94/network-policy-generator?color=green&logo=go&logoColor=b)
![helios-lb](https://img.shields.io/github/v/tag/somaz94/network-policy-generator?label=helios-lb&logo=kubernetes&logoColor=white)

A Kubernetes controller that automatically generates and manages Kubernetes Network Policies based on observed traffic patterns and user-defined rules.

## Description

The Network Policy Generator is a Kubernetes operator that simplifies the creation and management of Network Policies by providing two main operational modes:

- **Learning Mode**: Analyzes actual network traffic patterns within your cluster for a specified duration
- **Enforcing Mode**: Automatically generates and applies Network Policies based on learned patterns or predefined rules

This tool helps security teams and cluster administrators implement network segmentation more effectively by:
- Reducing manual Network Policy creation overhead
- Providing data-driven policy recommendations based on real traffic
- Supporting both permissive (allow-based) and restrictive (deny-based) policy approaches
- Enabling gradual transition from learning to enforcement phases

## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

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
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

## Usage Examples

### Learning Mode Example
```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: traffic-learner
spec:
  mode: "learning"
  duration: "24h"  # Analyze traffic for 24 hours
  policy:
    type: "allow"
```

### Enforcing Mode with Global Rules
```yaml
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: security-enforcer
spec:
  mode: "enforcing"
  policy:
    type: "deny"
    allowedNamespaces:
      - "kube-system"
      - "monitoring"
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
    - type: "allow"
      port: 443
      protocol: TCP
      direction: "ingress"
```

### Monitoring the Generator Status
```sh
kubectl get networkpolicygenerator
kubectl describe networkpolicygenerator <name>
```

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

## Features

- **Dual Operation Modes**: 
  - Learning mode for traffic pattern analysis
  - Enforcing mode for policy application
- **Flexible Policy Types**: 
  - Allow-based policies (default deny, explicit allow)
  - Deny-based policies (default allow, explicit deny)
- **Global Rule Management**: Define cluster-wide traffic rules
- **Namespace-based Controls**: Granular control over inter-namespace communication
- **Traffic Flow Monitoring**: Real-time observation of network traffic patterns
- **Gradual Migration**: Smooth transition from permissive to restrictive network policies

## Architecture

The Network Policy Generator consists of:

1. **CustomResourceDefinition (CRD)**: Defines the NetworkPolicyGenerator resource
2. **Controller**: Manages the lifecycle of network policies based on CRD specifications
3. **Traffic Monitor**: Analyzes network flows during learning phase
4. **Policy Engine**: Generates Kubernetes Network Policies from learned patterns

## Contributing

Issues and pull requests are welcome.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

