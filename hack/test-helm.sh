#!/bin/bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ENGINE="${1:-all}"
PASS=0
FAIL=0
SKIP=0
RELEASE_NAME="npg-test"
NAMESPACE="network-policy-generator-system"
CHART_DIR="./helm/network-policy-generator"
SAMPLES_DIR="config/samples"

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log_skip()  { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }

wait_for_pods() {
  local ns=$1
  local timeout=${2:-60}
  log_info "Waiting for pods in ${ns} to be ready (timeout: ${timeout}s)..."
  kubectl wait --for=condition=ready pod --all -n "$ns" --timeout="${timeout}s" 2>/dev/null || true
}

wait_for_resource() {
  local resource=$1
  local ns=$2
  local timeout=${3:-30}
  for i in $(seq 1 "$timeout"); do
    if kubectl get "$resource" -n "$ns" 2>/dev/null | grep -q .; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_phase() {
  local ns=$1
  local phase=$2
  local timeout=${3:-15}
  for i in $(seq 1 "$timeout"); do
    if kubectl get networkpolicygenerators -n "$ns" 2>/dev/null | grep -q "$phase"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cleanup_cr() {
  kubectl delete networkpolicygenerators -n test-ns1 --all --ignore-not-found 2>/dev/null || true
  kubectl delete networkpolicygenerators -n test-ns2 --all --ignore-not-found 2>/dev/null || true
  sleep 2
}

final_cleanup() {
  echo ""
  log_info "--- Final Cleanup (trap) ---"
  cleanup_cr
  kubectl delete -f "${SAMPLES_DIR}/test.yaml" --ignore-not-found 2>/dev/null || true
  kubectl delete ns test-ns1 test-ns2 test-ns3 --ignore-not-found 2>/dev/null || true
  kubectl delete crd networkpolicygenerators.security.policy.io --ignore-not-found 2>/dev/null || true
  helm uninstall "${RELEASE_NAME}" --no-hooks 2>/dev/null || true
  kubectl delete ns "$NAMESPACE" --ignore-not-found 2>/dev/null || true
}
trap final_cleanup EXIT

check_cilium() {
  if kubectl get crd ciliumnetworkpolicies.cilium.io >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# curl_test <from_pod> <from_ns> <target_svc> <target_ns> <expect: pass|fail> <test_label>
# Uses ClusterIP to bypass DNS. Retries up to 5 times with 5s intervals for policy propagation.
curl_test() {
  local pod=$1 ns=$2 svc=$3 target_ns=$4 expect=$5 label=$6
  local retries=5
  local exit_code=0

  # Resolve ClusterIP to bypass DNS resolution issues
  local cluster_ip
  cluster_ip=$(kubectl get svc "$svc" -n "$target_ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
  if [[ -z "$cluster_ip" ]]; then
    log_fail "${label}: could not get ClusterIP for ${svc} in ${target_ns}"
    return
  fi
  local url="http://${cluster_ip}:80"

  for attempt in $(seq 1 "$retries"); do
    exit_code=0
    kubectl exec "$pod" -n "$ns" -- curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$url" >/dev/null 2>&1 || exit_code=$?

    if [[ "$expect" == "pass" && $exit_code -eq 0 ]]; then
      log_pass "${label}: curl SUCCEEDED as expected"
      return
    elif [[ "$expect" == "fail" && $exit_code -ne 0 ]]; then
      log_pass "${label}: curl BLOCKED as expected"
      return
    fi

    if [[ $attempt -lt $retries ]]; then
      log_info "${label}: curl attempt ${attempt}/${retries} - retrying in 5s..."
      sleep 5
    fi
  done

  # All retries exhausted
  if [[ "$expect" == "pass" ]]; then
    log_fail "${label}: curl FAILED (expected success, exit_code=${exit_code})"
  else
    log_fail "${label}: curl SUCCEEDED (expected block)"
  fi
}

# ============================================================
# Setup - Helm Install
# ============================================================
log_info "========================================="
log_info "Network Policy Generator Helm Test"
log_info "Engine: ${ENGINE}"
log_info "========================================="

# Lint chart
log_info "Linting Helm chart..."
if helm lint "${CHART_DIR}" 2>&1 | grep -q "0 chart(s) failed"; then
  log_pass "Helm lint passed"
else
  log_fail "Helm lint failed"
fi

# Template render test
log_info "Testing Helm template rendering..."
if helm template test "${CHART_DIR}" > /dev/null 2>&1; then
  log_pass "Helm template renders successfully"
else
  log_fail "Helm template rendering failed"
fi

# Package test
log_info "Testing Helm package..."
PACKAGE_DIR=$(mktemp -d)
if helm package "${CHART_DIR}" -d "${PACKAGE_DIR}" > /dev/null 2>&1; then
  log_pass "Helm package created successfully"
  PACKAGE_FILE=$(ls "${PACKAGE_DIR}"/*.tgz 2>/dev/null | head -1)
  log_info "Package: ${PACKAGE_FILE}"
else
  log_fail "Helm package failed"
fi
rm -rf "${PACKAGE_DIR}"

# Clean up any previous failed release
helm uninstall "${RELEASE_NAME}" --no-hooks 2>/dev/null || true
kubectl delete crd networkpolicygenerators.security.policy.io --ignore-not-found 2>/dev/null || true

# Install via Helm
log_info "Installing chart via Helm..."
helm upgrade --install "${RELEASE_NAME}" "${CHART_DIR}" \
  --create-namespace \
  --set image.pullPolicy=Always \
  --wait \
  --timeout 120s 2>&1 | tail -5

# Verify Helm release
if helm status "${RELEASE_NAME}" 2>/dev/null | grep -q "deployed"; then
  log_pass "Helm release deployed successfully"
else
  log_fail "Helm release not in deployed status"
fi

# Verify controller pod
log_info "Waiting for controller pod to exist..."
for i in $(seq 1 30); do
  if kubectl get pod -l control-plane=controller-manager -n "$NAMESPACE" 2>/dev/null | grep -q .; then
    break
  fi
  sleep 2
done
log_info "Waiting for controller to be ready..."
if kubectl wait --for=condition=ready pod -l control-plane=controller-manager \
  -n "$NAMESPACE" --timeout=120s 2>/dev/null; then
  log_pass "Controller pod is running"
else
  log_fail "Controller pod not ready"
fi

# Verify CRD installed
if kubectl get crd networkpolicygenerators.security.policy.io >/dev/null 2>&1; then
  log_pass "CRD installed via Helm"
else
  log_fail "CRD not found"
fi

# Verify RBAC
if kubectl get clusterrole network-policy-generator-manager-role >/dev/null 2>&1; then
  log_pass "ClusterRole created"
else
  log_fail "ClusterRole not found"
fi

# Verify Service
if kubectl get svc -n "$NAMESPACE" 2>/dev/null | grep -q "metrics"; then
  log_pass "Metrics service created"
else
  log_fail "Metrics service not found"
fi

# ============================================================
# Create test resources
# ============================================================
log_info "Creating test namespaces and pods..."
kubectl create ns test-ns1 --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns test-ns2 --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns test-ns3 --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${SAMPLES_DIR}/test.yaml"
wait_for_pods test-ns1
wait_for_pods test-ns2
wait_for_pods test-ns3 90

# ============================================================
# Kubernetes Engine Tests
# ============================================================
if [[ "$ENGINE" == "all" || "$ENGINE" == "kubernetes" ]]; then
  echo ""
  log_info "--- Kubernetes NetworkPolicy Tests (Helm) ---"

  # Test: Deny Policy
  log_info "[Test] Kubernetes Deny Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-deny.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s Deny: CR created with Enforcing phase"
  else
    log_fail "K8s Deny: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "K8s Deny: NetworkPolicy generated"
  else
    log_fail "K8s Deny: NetworkPolicy not generated"
  fi
  # Curl: test-ns3 -> test-ns1 should be BLOCKED (test-ns3 not in allowedNamespaces)
  curl_test test-client test-ns3 test-service1 test-ns1 fail "K8s Deny"
  cleanup_cr
  sleep 2
  if ! kubectl get networkpolicies -n test-ns1 2>/dev/null | grep -q "generated"; then
    log_pass "K8s Deny: Finalizer cleanup successful"
  else
    log_fail "K8s Deny: Finalizer cleanup failed"
  fi

  # Test: Allow Policy
  log_info "[Test] Kubernetes Allow Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-allow.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s Allow: CR created with Enforcing phase"
  else
    log_fail "K8s Allow: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "K8s Allow: NetworkPolicy generated"
  else
    log_fail "K8s Allow: NetworkPolicy not generated"
  fi
  # Curl: test-ns3 -> test-ns1 should SUCCEED (allow type uses NotIn, test-ns3 not in deniedNamespaces)
  curl_test test-client test-ns3 test-service1 test-ns1 pass "K8s Allow"
  cleanup_cr

  # Test: Pod Selector Policy
  log_info "[Test] Kubernetes Pod Selector Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-pod-selector.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s PodSelector: CR created with Enforcing phase"
  else
    log_fail "K8s PodSelector: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "K8s PodSelector: NetworkPolicy generated"
    # Verify podSelector labels are set
    POD_SELECTOR=$(kubectl get networkpolicy -n test-ns1 -o jsonpath='{.items[0].spec.podSelector.matchLabels}' 2>/dev/null)
    if echo "$POD_SELECTOR" | grep -q "web"; then
      log_pass "K8s PodSelector: podSelector labels applied correctly"
    else
      log_fail "K8s PodSelector: podSelector labels not found"
    fi
  else
    log_fail "K8s PodSelector: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test: CIDR Rules Policy
  log_info "[Test] Kubernetes CIDR Rules Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cidr-rules.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s CIDR: CR created with Enforcing phase"
  else
    log_fail "K8s CIDR: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "K8s CIDR: NetworkPolicy generated"
    # Verify CIDR rules exist in the policy
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    if echo "$NP_JSON" | grep -q "10.0.0.0/8"; then
      log_pass "K8s CIDR: Egress CIDR rule (10.0.0.0/8) found"
    else
      log_fail "K8s CIDR: Egress CIDR rule not found"
    fi
    if echo "$NP_JSON" | grep -q "192.168.1.0/24"; then
      log_pass "K8s CIDR: Ingress CIDR rule (192.168.1.0/24) found"
    else
      log_fail "K8s CIDR: Ingress CIDR rule not found"
    fi
  else
    log_fail "K8s CIDR: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test: Named Port Policy
  log_info "[Test] Kubernetes Named Port Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-named-port.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s NamedPort: CR created with Enforcing phase"
  else
    log_fail "K8s NamedPort: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "K8s NamedPort: NetworkPolicy generated"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    if echo "$NP_JSON" | grep -q '"http"'; then
      log_pass "K8s NamedPort: Named port 'http' found in policy"
    else
      log_fail "K8s NamedPort: Named port 'http' not found"
    fi
    if echo "$NP_JSON" | grep -q '"grpc"'; then
      log_pass "K8s NamedPort: Named port 'grpc' found in policy"
    else
      log_fail "K8s NamedPort: Named port 'grpc' not found"
    fi
  else
    log_fail "K8s NamedPort: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test: Dry Run Policy
  log_info "[Test] Kubernetes Dry Run Mode"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-dry-run.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s DryRun: CR created with Enforcing phase"
  else
    log_fail "K8s DryRun: CR not in Enforcing phase"
  fi
  # In dry-run mode, no NetworkPolicy should be created
  if ! kubectl get networkpolicies -n test-ns1 2>/dev/null | grep -q "generated"; then
    log_pass "K8s DryRun: No NetworkPolicy created (dry-run mode)"
  else
    log_fail "K8s DryRun: NetworkPolicy unexpectedly created in dry-run mode"
  fi
  # Verify generated policies are stored in status
  GENERATED=$(kubectl get networkpolicygenerators -n test-ns1 -o jsonpath='{.items[0].status.generatedPolicies}' 2>/dev/null)
  if [[ -n "$GENERATED" && "$GENERATED" != "[]" ]]; then
    log_pass "K8s DryRun: Generated policies stored in status"
  else
    log_fail "K8s DryRun: Generated policies not found in status"
  fi
  cleanup_cr
  sleep 2

  # Test: Full Features (combined)
  log_info "[Test] Kubernetes Full Features (pod-selector + CIDR + named-port)"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-full-features.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "K8s Full: CR created with Enforcing phase"
  else
    log_fail "K8s Full: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "K8s Full: NetworkPolicy generated"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    # Check podSelector
    if echo "$NP_JSON" | grep -q "payment-service"; then
      log_pass "K8s Full: podSelector applied"
    else
      log_fail "K8s Full: podSelector not found"
    fi
    # Check CIDR rule
    if echo "$NP_JSON" | grep -q "10.0.0.0/8"; then
      log_pass "K8s Full: CIDR rule applied"
    else
      log_fail "K8s Full: CIDR rule not found"
    fi
    # Check named port
    if echo "$NP_JSON" | grep -q '"metrics"'; then
      log_pass "K8s Full: Named port applied"
    else
      log_fail "K8s Full: Named port not found"
    fi
    # Check policy diff in status
    DIFF=$(kubectl get networkpolicygenerators -n test-ns1 -o jsonpath='{.items[0].status.policyDiff}' 2>/dev/null)
    if [[ -n "$DIFF" && "$DIFF" != "[]" ]]; then
      log_pass "K8s Full: Policy diff tracked in status"
    else
      log_fail "K8s Full: Policy diff not found in status"
    fi
  else
    log_fail "K8s Full: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test: Event Recording
  log_info "[Test] Event Recording Verification"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-deny.yaml" -n test-ns1
  sleep 5
  EVENTS=$(kubectl get events -n test-ns1 --field-selector involvedObject.kind=NetworkPolicyGenerator 2>/dev/null)
  if echo "$EVENTS" | grep -qi "PolicyApplied\|Normal"; then
    log_pass "Events: Events recorded for NetworkPolicyGenerator"
  else
    log_fail "Events: No events found for NetworkPolicyGenerator"
  fi
  cleanup_cr
  sleep 2

  # Test: Prometheus Metrics
  log_info "[Test] Prometheus Metrics Verification"
  METRICS_SVC="network-policy-generator-controller-manager-metrics-service"
  if kubectl get svc "$METRICS_SVC" -n "$NAMESPACE" >/dev/null 2>&1; then
    # Create temporary ClusterRoleBinding so the SA token can access /metrics
    SA_NAME="network-policy-generator-controller-manager"
    kubectl create clusterrolebinding npg-metrics-test-binding \
      --clusterrole=network-policy-generator-metrics-reader \
      --serviceaccount="${NAMESPACE}:${SA_NAME}" 2>/dev/null || true

    # Port-forward to controller pod directly (distroless image has no curl)
    METRICS_POD=$(kubectl get pod -l control-plane=controller-manager -n "$NAMESPACE" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    kubectl port-forward -n "$NAMESPACE" "pod/${METRICS_POD}" 18443:8443 >/dev/null 2>&1 &
    PF_PID=$!
    sleep 3

    # Use SA token for authentication
    TOKEN=$(kubectl create token "${SA_NAME}" -n "$NAMESPACE" 2>/dev/null || true)
    if [[ -n "$TOKEN" ]]; then
      METRICS=$(curl -sk -H "Authorization: Bearer ${TOKEN}" https://localhost:18443/metrics 2>/dev/null || true)
    else
      METRICS=$(curl -sk https://localhost:18443/metrics 2>/dev/null || true)
    fi
    kill $PF_PID 2>/dev/null || true
    wait $PF_PID 2>/dev/null || true

    # Cleanup temporary binding
    kubectl delete clusterrolebinding npg-metrics-test-binding 2>/dev/null || true

    if [[ -z "$METRICS" ]]; then
      log_info "Metrics: No metrics response received (debug: token=${TOKEN:+set}, pod=${METRICS_POD})"
    fi

    if echo "$METRICS" | grep -q "npg_reconcile_total"; then
      log_pass "Metrics: npg_reconcile_total metric found"
    else
      log_fail "Metrics: npg_reconcile_total metric not found"
    fi
    if echo "$METRICS" | grep -q "npg_reconcile_duration_seconds"; then
      log_pass "Metrics: npg_reconcile_duration_seconds metric found"
    else
      log_fail "Metrics: npg_reconcile_duration_seconds metric not found"
    fi
    if echo "$METRICS" | grep -q "npg_policy_operations_total"; then
      log_pass "Metrics: npg_policy_operations_total metric found"
    else
      log_fail "Metrics: npg_policy_operations_total metric not found"
    fi
  else
    log_skip "Metrics: Metrics service not found, skipping metrics test"
  fi

  # Test: Multi-Namespace
  log_info "[Test] Multi-Namespace Policy"
  kubectl apply -f "${SAMPLES_DIR}/test-policy.yaml"
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Multi-NS: test-ns1 CR in Enforcing phase"
  else
    log_fail "Multi-NS: test-ns1 CR not in Enforcing phase"
  fi
  if wait_for_phase test-ns2 "Enforcing"; then
    log_pass "Multi-NS: test-ns2 CR in Enforcing phase"
  else
    log_fail "Multi-NS: test-ns2 CR not in Enforcing phase"
  fi
  kubectl delete networkpolicygenerators -A --all --ignore-not-found 2>/dev/null || true
  sleep 2
fi

# ============================================================
# Cilium Engine Tests
# ============================================================
if [[ "$ENGINE" == "all" || "$ENGINE" == "cilium" ]]; then
  echo ""
  if check_cilium; then
    log_info "--- Cilium NetworkPolicy Tests (Helm) ---"

    # Test: Cilium Deny Policy
    log_info "[Test] Cilium Deny Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cilium-deny.yaml" -n test-ns1
    if wait_for_phase test-ns1 "Enforcing"; then
      log_pass "Cilium Deny: CR created with Enforcing phase"
    else
      log_fail "Cilium Deny: CR not in Enforcing phase"
    fi
    if wait_for_resource "ciliumnetworkpolicies" "test-ns1" 10; then
      log_pass "Cilium Deny: CiliumNetworkPolicy generated"
    else
      log_fail "Cilium Deny: CiliumNetworkPolicy not generated"
    fi
    if kubectl get ciliumnetworkpolicies -n test-ns1 2>/dev/null | grep -q "True"; then
      log_pass "Cilium Deny: CiliumNetworkPolicy is Valid"
    else
      log_fail "Cilium Deny: CiliumNetworkPolicy is not Valid"
    fi
    # Curl: test-ns3 -> test-ns1 should SUCCEED (test-ns3 in allowedNamespaces)
    curl_test test-client test-ns3 test-service1 test-ns1 pass "Cilium Deny"
    cleanup_cr
    sleep 2
    if ! kubectl get ciliumnetworkpolicies -n test-ns1 2>/dev/null | grep -q "generated"; then
      log_pass "Cilium Deny: Finalizer cleanup successful"
    else
      log_fail "Cilium Deny: Finalizer cleanup failed"
    fi

    # Test: Cilium Allow Policy
    log_info "[Test] Cilium Allow Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cilium-allow.yaml" -n test-ns1
    if wait_for_phase test-ns1 "Enforcing"; then
      log_pass "Cilium Allow: CR created with Enforcing phase"
    else
      log_fail "Cilium Allow: CR not in Enforcing phase"
    fi
    if wait_for_resource "ciliumnetworkpolicies" "test-ns1" 10; then
      log_pass "Cilium Allow: CiliumNetworkPolicy generated"
    else
      log_fail "Cilium Allow: CiliumNetworkPolicy not generated"
    fi
    if kubectl get ciliumnetworkpolicies -n test-ns1 2>/dev/null | grep -q "True"; then
      log_pass "Cilium Allow: CiliumNetworkPolicy is Valid"
    else
      log_fail "Cilium Allow: CiliumNetworkPolicy is not Valid"
    fi
    # Curl: test-ns3 -> test-ns1 should be BLOCKED (CiliumNetworkPolicy default-deny applies
    # when any rule exists; test-ns3 is cluster-internal and does not match "world" entity)
    curl_test test-client test-ns3 test-service1 test-ns1 fail "Cilium Allow"
    cleanup_cr
  else
    log_skip "Cilium CRD not found, skipping Cilium tests"
  fi
fi

# ============================================================
# Helm Upgrade Test
# ============================================================
echo ""
log_info "--- Helm Upgrade Test ---"
if helm upgrade "${RELEASE_NAME}" "${CHART_DIR}" --wait --timeout 120s 2>&1 | grep -q "has been upgraded"; then
  log_pass "Helm upgrade successful"
else
  log_fail "Helm upgrade failed"
fi

# ============================================================
# Summary
# ============================================================
echo ""
log_info "========================================="
log_info "Helm Test Summary"
log_info "========================================="
echo -e "${GREEN}PASSED: ${PASS}${NC}"
echo -e "${RED}FAILED: ${FAIL}${NC}"
echo -e "${YELLOW}SKIPPED: ${SKIP}${NC}"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
