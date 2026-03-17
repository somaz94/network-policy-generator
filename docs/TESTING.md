# Network Policy Generator - Test Guide

<br/>

## Prerequisites

- Kubernetes cluster (Kind, Minikube, EKS, GKE, etc.)
- `kubectl` configured
- For Cilium tests: Cilium CNI installed on the cluster
- For Calico tests: Calico CNI installed on the cluster

<br/>

## 1. Unit Tests

```bash
make test
```

<br/>

## 2. End-to-End Tests (e2e)

Run end-to-end tests using [Kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker):

```bash
make test-e2e
```

Prerequisites:
- Kind must be installed
- A Kind cluster must be running (`kind create cluster`)

This target runs `manifests`, `generate`, `fmt`, and `vet` before executing the e2e test suite located in `test/e2e/` using Ginkgo.

> **NOTE**: You can skip Prometheus and CertManager installation by setting:
> ```bash
> PROMETHEUS_INSTALL_SKIP=true CERT_MANAGER_INSTALL_SKIP=true make test-e2e
> ```

<br/>

## 3. Integration Test (Automated)

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

# Calico engine only
make test-integration ENGINE=calico

# All engines (default)
make test-integration ENGINE=all
```

<br/>

## 4. Helm Chart Test (Automated)

Run Helm chart tests (lint, template, install, upgrade, policy tests, uninstall):

```bash
make test-helm
```

Options:

```bash
# Kubernetes engine only (skip Cilium tests)
make test-helm ENGINE=kubernetes

# Cilium engine only
make test-helm ENGINE=cilium

# Calico engine only
make test-helm ENGINE=calico

# All engines (default)
make test-helm ENGINE=all
```

Test coverage:
- Helm lint, template render, package
- Helm install & release verification
- Controller pod, CRD, RBAC, Service verification
- Kubernetes/Cilium/Calico NetworkPolicy CR tests (same as integration)
- Policy Template tests (web-app, database)
- Helm upgrade test
- Helm uninstall & CRD cleanup hook verification

<br/>

## 5. Manual Deploy Test

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

## 6. Kubernetes NetworkPolicy Tests

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

## 6-1. Advanced Feature Tests

<br/>

### Test D-1: Pod Label Selector

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-pod-selector.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
# Verify podSelector labels are applied
kubectl get networkpolicy -n test-ns1 -o jsonpath='{.items[0].spec.podSelector.matchLabels}'
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test D-2: CIDR Rules

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-cidr-rules.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
# Verify CIDR rules in egress/ingress
kubectl get networkpolicy -n test-ns1 -o yaml | grep -A5 cidr
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test D-3: Named Port

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-named-port.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
# Verify named ports (http, grpc)
kubectl get networkpolicy -n test-ns1 -o yaml | grep -A2 port
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test D-4: Dry Run Mode

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-dry-run.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
# No NetworkPolicy should be created
kubectl get networkpolicies -n test-ns1
# Generated policies should be in status
kubectl get networkpolicygenerator dry-run-example -n test-ns1 -o jsonpath='{.status.generatedPolicies}'
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test D-5: Full Features (Pod Selector + CIDR + Named Port + Diff)

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-full-features.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
# Verify policy diff in status
kubectl get networkpolicygenerator full-features-example -n test-ns1 -o jsonpath='{.status.policyDiff}'
# Verify applied policies count
kubectl get networkpolicygenerator full-features-example -n test-ns1 -o jsonpath='{.status.appliedPoliciesCount}'
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

---

## 6-2. Operational Feature Tests

<br/>

### Test D-6: Event Recording

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-deny.yaml -n test-ns1
```

Check:

```bash
# Verify Kubernetes Events are emitted
kubectl get events -n test-ns1 --field-selector involvedObject.kind=NetworkPolicyGenerator
```

Expected events: `PolicyApplied`, `ModeTransition`, `PolicyDeleted`, etc.

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test D-7: Prometheus Metrics

```bash
NAMESPACE="network-policy-generator-system"
METRICS_SVC="network-policy-generator-controller-manager-metrics-service"

# Port-forward metrics service (controller uses distroless image without curl)
kubectl port-forward -n "$NAMESPACE" "svc/${METRICS_SVC}" 18443:8443 &
PF_PID=$!
sleep 2

# Create SA token and fetch metrics
TOKEN=$(kubectl create token network-policy-generator-controller-manager -n "$NAMESPACE")
curl -sk -H "Authorization: Bearer ${TOKEN}" https://localhost:18443/metrics | grep npg_

# Cleanup
kill $PF_PID
```

Expected metrics: `npg_reconcile_total`, `npg_reconcile_duration_seconds`, `npg_policies_applied`, `npg_policy_operations_total`, `npg_generators_active`, `npg_dry_run_total`, `npg_validation_errors_total`

<br/>

### Test D-8: Webhook Validation (requires cert-manager)

> **Note**: Webhook must be enabled with `--enable-webhooks` flag and cert-manager installed.

```bash
# Try creating an invalid CR (should be rejected)
kubectl apply -f - <<EOF
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: invalid-test
  namespace: test-ns1
spec:
  mode: "invalid"
  policy:
    type: "deny"
EOF
```

Expected: admission webhook should reject with `Unsupported value: "invalid"`.

---

## 6-3. Calico NetworkPolicy Tests

> **Requires Calico CNI installed on the cluster**

<br/>

### Test G: Calico Deny Policy

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-calico-deny.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies.crd.projectcalico.org -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test H: Calico Allow Policy

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-calico-allow.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies.crd.projectcalico.org -n test-ns1
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

---

## 6-4. Policy Template Tests

<br/>

### Test I: Web-App Template

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-template-web-app.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
# Verify template rules (port 80, 443) are applied
kubectl get networkpolicy -n test-ns1 -o yaml | grep -A2 port
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

<br/>

### Test J: Database Template

```bash
kubectl apply -f config/samples/security_v1_networkpolicygenerator-template-database.yaml -n test-ns1
```

Check:

```bash
kubectl get networkpolicygenerators -n test-ns1
kubectl get networkpolicies -n test-ns1
# Verify DB port rules (5432, 3306, etc.) are applied
kubectl get networkpolicy -n test-ns1 -o yaml | grep -A2 port
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

---

## 6-5. Learning Mode Suggestion Tests

<br/>

### Test K: Learning Mode with Suggestions

```bash
kubectl apply -f - <<EOF
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: test-learning-suggestions
  namespace: test-ns1
spec:
  mode: "learning"
  duration: "30s"
  policy:
    type: "deny"
EOF
```

Check:

```bash
# Should be "Learning" phase
kubectl get networkpolicygenerators -n test-ns1

# Wait 35 seconds for transition
sleep 35

# Should be "Enforcing" phase with suggestions
kubectl get networkpolicygenerators -n test-ns1

# Check suggested namespaces
kubectl get networkpolicygenerator test-learning-suggestions -n test-ns1 -o jsonpath='{.status.suggestedNamespaces}'

# Check suggested rules
kubectl get networkpolicygenerator test-learning-suggestions -n test-ns1 -o jsonpath='{.status.suggestedRules}'
```

Cleanup:

```bash
kubectl delete networkpolicygenerators -n test-ns1 --all
```

---

## 7. Cilium NetworkPolicy Tests

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

## 8. Multi-Namespace Test (test-policy.yaml)

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

## 9. Finalizer / Deletion Test

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

## 10. Full Cleanup

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
| `security_v1_networkpolicygenerator-pod-selector.yaml` | kubernetes (default) | deny | Pod label selector targeting |
| `security_v1_networkpolicygenerator-cidr-rules.yaml` | kubernetes (default) | deny | CIDR-based egress/ingress rules |
| `security_v1_networkpolicygenerator-named-port.yaml` | kubernetes (default) | deny | Named port (`http`, `grpc`) rules |
| `security_v1_networkpolicygenerator-dry-run.yaml` | kubernetes (default) | deny | Dry run mode (preview only) |
| `security_v1_networkpolicygenerator-full-features.yaml` | kubernetes (default) | deny | All features combined |
| `security_v1_networkpolicygenerator-cilium-allow.yaml` | cilium | allow | Cilium allow policy |
| `security_v1_networkpolicygenerator-cilium-deny.yaml` | cilium | deny | Cilium deny policy |
| `security_v1_networkpolicygenerator-calico-allow.yaml` | calico | allow | Calico allow policy |
| `security_v1_networkpolicygenerator-calico-deny.yaml` | calico | deny | Calico deny policy |
| `security_v1_networkpolicygenerator-template-web-app.yaml` | kubernetes (default) | deny | Web-app template (ports 80, 443) |
| `security_v1_networkpolicygenerator-template-database.yaml` | kubernetes (default) | deny | Database template (ports 3306, 5432, 6379, 27017) |
| `test.yaml` | - | - | Test pods (nginx) and services |
| `test-policy.yaml` | kubernetes (default) | deny | Multi-namespace test |
