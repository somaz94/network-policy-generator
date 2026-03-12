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
NAMESPACE="network-policy-generator-system"
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

cleanup_cr() {
  kubectl delete networkpolicygenerators -n test-ns1 --all --ignore-not-found 2>/dev/null || true
  kubectl delete networkpolicygenerators -n test-ns2 --all --ignore-not-found 2>/dev/null || true
  sleep 2
}

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
# Setup
# ============================================================
log_info "========================================="
log_info "Network Policy Generator Integration Test"
log_info "Engine: ${ENGINE}"
log_info "========================================="

# Deploy controller
log_info "Deploying controller..."
make deploy 2>&1 | tail -5
# Force image pull to ensure latest image is used during testing
kubectl patch deployment network-policy-generator-controller-manager -n "$NAMESPACE" \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"manager","imagePullPolicy":"Always"}]}}}}' 2>/dev/null || true

# Wait for controller pod to exist first, then wait for ready
log_info "Waiting for controller to be ready..."
for i in $(seq 1 30); do
  if kubectl get pod -l control-plane=controller-manager -n "$NAMESPACE" 2>/dev/null | grep -q .; then
    break
  fi
  sleep 2
done
if ! kubectl wait --for=condition=ready pod -l control-plane=controller-manager \
  -n "$NAMESPACE" --timeout=180s; then
  log_fail "Failed to deploy controller in ${NAMESPACE}"
  exit 1
fi

# Create test namespaces
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
  log_info "--- Kubernetes NetworkPolicy Tests ---"

  # Test A: Deny Policy
  log_info "[Test A] Kubernetes Deny Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-deny.yaml" -n test-ns1
  sleep 3
  if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Enforcing"; then
    log_pass "Test A: CR created with Enforcing phase"
  else
    log_fail "Test A: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test A: NetworkPolicy generated"
  else
    log_fail "Test A: NetworkPolicy not generated"
  fi
  # Curl: test-ns3 -> test-ns1 should be BLOCKED (test-ns3 not in allowedNamespaces)
  curl_test test-client test-ns3 test-service1 test-ns1 fail "Test A"
  cleanup_cr
  sleep 2
  if ! kubectl get networkpolicies -n test-ns1 2>/dev/null | grep -q "generated"; then
    log_pass "Test A: NetworkPolicy cleaned up after CR deletion (finalizer)"
  else
    log_fail "Test A: NetworkPolicy not cleaned up"
  fi

  # Test B: Allow Policy
  log_info "[Test B] Kubernetes Allow Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-allow.yaml" -n test-ns1
  sleep 3
  if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Enforcing"; then
    log_pass "Test B: CR created with Enforcing phase"
  else
    log_fail "Test B: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test B: NetworkPolicy generated"
  else
    log_fail "Test B: NetworkPolicy not generated"
  fi
  # Curl: test-ns3 -> test-ns1 should SUCCEED (allow type uses NotIn, test-ns3 not in deniedNamespaces)
  curl_test test-client test-ns3 test-service1 test-ns1 pass "Test B"
  cleanup_cr

  # Test C: Learning -> Enforcing
  log_info "[Test C] Learning -> Enforcing Mode"
  kubectl apply -f - <<EOF
apiVersion: security.policy.io/v1
kind: NetworkPolicyGenerator
metadata:
  name: test-learning
  namespace: test-ns1
spec:
  mode: "learning"
  duration: "30s"
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
  sleep 3
  if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Learning"; then
    log_pass "Test C: CR starts in Learning phase"
  else
    log_fail "Test C: CR not in Learning phase"
  fi
  log_info "Waiting 35s for learning -> enforcing transition..."
  sleep 35
  if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Enforcing"; then
    log_pass "Test C: Transitioned to Enforcing phase"
  else
    log_fail "Test C: Did not transition to Enforcing"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test C: NetworkPolicy generated after enforcing"
  else
    log_fail "Test C: NetworkPolicy not generated after enforcing"
  fi
  cleanup_cr

  # Test D: Multi-Namespace
  log_info "[Test D] Multi-Namespace Policy (test-policy.yaml)"
  kubectl apply -f "${SAMPLES_DIR}/test-policy.yaml"
  sleep 3
  if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Enforcing"; then
    log_pass "Test D: test-ns1 CR in Enforcing phase"
  else
    log_fail "Test D: test-ns1 CR not in Enforcing phase"
  fi
  if kubectl get networkpolicygenerators -n test-ns2 2>/dev/null | grep -q "Enforcing"; then
    log_pass "Test D: test-ns2 CR in Enforcing phase"
  else
    log_fail "Test D: test-ns2 CR not in Enforcing phase"
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
    log_info "--- Cilium NetworkPolicy Tests ---"

    # Test E: Cilium Deny Policy
    log_info "[Test E] Cilium Deny Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cilium-deny.yaml" -n test-ns1
    sleep 3
    if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Enforcing"; then
      log_pass "Test E: CR created with Enforcing phase"
    else
      log_fail "Test E: CR not in Enforcing phase"
    fi
    if wait_for_resource "ciliumnetworkpolicies" "test-ns1" 10; then
      log_pass "Test E: CiliumNetworkPolicy generated"
    else
      log_fail "Test E: CiliumNetworkPolicy not generated"
    fi
    # Check Valid status
    if kubectl get ciliumnetworkpolicies -n test-ns1 2>/dev/null | grep -q "True"; then
      log_pass "Test E: CiliumNetworkPolicy is Valid"
    else
      log_fail "Test E: CiliumNetworkPolicy is not Valid"
    fi
    # Curl: test-ns3 -> test-ns1 should SUCCEED (test-ns3 in allowedNamespaces)
    curl_test test-client test-ns3 test-service1 test-ns1 pass "Test E"
    cleanup_cr
    sleep 2
    if ! kubectl get ciliumnetworkpolicies -n test-ns1 2>/dev/null | grep -q "generated"; then
      log_pass "Test E: CiliumNetworkPolicy cleaned up (finalizer)"
    else
      log_fail "Test E: CiliumNetworkPolicy not cleaned up"
    fi

    # Test F: Cilium Allow Policy
    log_info "[Test F] Cilium Allow Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cilium-allow.yaml" -n test-ns1
    sleep 5
    if kubectl get networkpolicygenerators -n test-ns1 2>/dev/null | grep -q "Enforcing"; then
      log_pass "Test F: CR created with Enforcing phase"
    else
      log_fail "Test F: CR not in Enforcing phase"
    fi
    if wait_for_resource "ciliumnetworkpolicies" "test-ns1" 10; then
      log_pass "Test F: CiliumNetworkPolicy generated"
    else
      log_fail "Test F: CiliumNetworkPolicy not generated"
    fi
    if kubectl get ciliumnetworkpolicies -n test-ns1 2>/dev/null | grep -q "True"; then
      log_pass "Test F: CiliumNetworkPolicy is Valid"
    else
      log_fail "Test F: CiliumNetworkPolicy is not Valid"
    fi
    # Curl: test-ns3 -> test-ns1 should be BLOCKED (CiliumNetworkPolicy default-deny applies
    # when any rule exists; test-ns3 is cluster-internal and does not match "world" entity)
    curl_test test-client test-ns3 test-service1 test-ns1 fail "Test F"
    cleanup_cr
  else
    log_skip "Cilium CRD not found, skipping Cilium tests"
  fi
fi

# ============================================================
# Cleanup
# ============================================================
echo ""
log_info "--- Cleanup ---"
kubectl delete -f "${SAMPLES_DIR}/test.yaml" --ignore-not-found 2>/dev/null || true
kubectl delete ns test-ns1 test-ns2 test-ns3 --ignore-not-found 2>/dev/null || true
make undeploy 2>&1 | tail -3

# ============================================================
# Summary
# ============================================================
echo ""
log_info "========================================="
log_info "Test Summary"
log_info "========================================="
echo -e "${GREEN}PASSED: ${PASS}${NC}"
echo -e "${RED}FAILED: ${FAIL}${NC}"
echo -e "${YELLOW}SKIPPED: ${SKIP}${NC}"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
