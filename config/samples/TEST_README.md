# Network Policy Generator - Test Guide

<br/>

## Prerequisites

- Kubernetes cluster (Kind, Minikube, EKS, GKE, etc.)
- `kubectl` configured
- For Cilium tests: Cilium CNI installed on the cluster

<br/>

## 1. Unit Tests

```bash
make test
```

<br/>

## 2. Integration Test (Automated)

Run all sample tests automatically:

```bash
make test-integration
```

Options:

```bash
# Kubernetes engine only (skip Cilium tests)
make test-integration ENGINE=kubernetes

# Cilium engine only
make test-integration ENGINE=cilium

# All engines (default)
make test-integration ENGINE=all
```

<br/>

## 3. Manual Deploy Test

<br/>

### Step 1: Deploy Controller (CRD + RBAC + Controller)

`make deploy` includes CRD installation via `config/default/kustomization.yaml`.
The image tag is defined in Makefile (`IMG` variable), so no need to specify it.

```bash
make deploy
```

<br/>

### Step 2: Verify Controller is Running

```bash
kubectl get pods -n network-policy-generator-system
```

<br/>

### Step 3: Create Test Namespaces and Pods

```bash
kubectl create ns test-ns1
kubectl create ns test-ns2
kubectl create ns test-ns3

kubectl apply -f config/samples/test.yaml
```

Verify pods are running:

```bash
kubectl get pods -n test-ns1
kubectl get pods -n test-ns2
kubectl get pods -n test-ns3
```

---

## 4. Kubernetes NetworkPolicy Tests

<br/>

### Test A: Deny Policy (allow only specific namespaces)

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-deny.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
kubectl describe networkpolicy -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test B: Allow Policy (deny specific namespaces)

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-allow.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test C: Learning -> Enforcing Mode

```bash
kubectl apply -f - <<EOF
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: test-learning
  namespace: test-ns1
spec:
  mode: "learning"
  duration: "1m"
  policy:
    type: "deny"
    allowedNamespaces:
      - "test-ns3"
  globalRules:
    - type: "allow"
      port: 80
      protocol: TCP
      direction: "ingress"
EOF
```

Check:

```bash
# Should be "Learning" phase
kubectl get networkpolicygenerators -n test-ns1

# Wait 1 minute, then check again (should switch to "Enforcing")
kubectl get networkpolicygenerators -n test-ns1

# NetworkPolicy should be created after switching to enforcing
kubectl get networkpolicies -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

---

## 5. Cilium NetworkPolicy Tests

> **Requires Cilium CNI installed on the cluster**

<br/>

### Test D: Cilium Deny Policy

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-cilium-deny.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get ciliumnetworkpolicies -n test-ns1
kubectl describe ciliumnetworkpolicy -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test E: Cilium Allow Policy

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-cilium-allow.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get ciliumnetworkpolicies -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

---

## 6. Multi-Namespace Test (test-policy.yaml)

```bash
kubectl apply -f config/samples/test-policy.yaml
```

Check:

```bash
kubectl get networkpolicygenerators -A
kubectl get networkpolicies -A
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -A --all
```

---

## 7. Finalizer / Deletion Test

Verify that deleting a NetworkPolicyGenerator also removes the generated policies:

```bash
# Apply a policy
kubectl apply -f config/samples/security_v1_networkpolicygenerator-deny.yaml -n test-ns1

# Check NetworkPolicy exists
kubectl get networkpolicies -n test-ns1

# Delete the generator
kubectl delete networkpolicygenerators -n test-ns1 --all

# NetworkPolicy should be removed
kubectl get networkpolicies -n test-ns1
```

---

## 8. Full Cleanup

```bash
# Remove all test resources
kubectl delete -f config/samples/test.yaml --ignore-not-found
kubectl delete ns test-ns1 test-ns2 test-ns3 --ignore-not-found

# Undeploy controller (removes CRD + RBAC + Controller)
make undeploy
```

---

## Sample Files

| File | Engine | Policy Type | Description |
|------|--------|-------------|-------------|
| `security_v1_networkpolicygenerator.yaml` | kubernetes (default) | deny | Basic deny policy with global rules |
| `security_v1_networkpolicygenerator-allow.yaml` | kubernetes (default) | allow | Allow policy - deny specific namespaces |
| `security_v1_networkpolicygenerator-deny.yaml` | kubernetes (default) | deny | Deny policy - allow specific namespaces |
| `security_v1_networkpolicygenerator-cilium-allow.yaml` | cilium | allow | Cilium allow policy |
| `security_v1_networkpolicygenerator-cilium-deny.yaml` | cilium | deny | Cilium deny policy |
| `test.yaml` | - | - | Test pods (nginx) and services |
| `test-policy.yaml` | kubernetes (default) | deny | Multi-namespace test |
