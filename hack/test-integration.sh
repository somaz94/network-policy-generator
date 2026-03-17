#!/bin/bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ENGINE="${1:-auto}"
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
  kubectl delete clusterrolebinding npg-metrics-test-binding --ignore-not-found 2>/dev/null || true
  make undeploy || true
}
trap final_cleanup EXIT

check_cilium() {
  if kubectl get crd ciliumnetworkpolicies.cilium.io >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

check_calico() {
  if kubectl get crd networkpolicies.crd.projectcalico.org >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# Auto-detect CNI when ENGINE is "auto" (default)
if [[ "$ENGINE" == "auto" ]]; then
  ENGINE="kubernetes"  # always test kubernetes
  if check_cilium; then
    ENGINE="${ENGINE}+cilium"
    log_info "Detected Cilium CNI"
  fi
  if check_calico; then
    ENGINE="${ENGINE}+calico"
    log_info "Detected Calico CNI"
  fi
  log_info "Auto-detected engines: ${ENGINE}"
fi

should_test() {
  local engine=$1
  [[ "$ENGINE" == "all" ]] || [[ "$ENGINE" == *"$engine"* ]]
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

# Clean up previous deployment if exists
log_info "Cleaning up previous deployment..."
make undeploy 2>/dev/null || true
sleep 3

# Deploy controller
log_info "Deploying controller..."
make deploy 2>&1 | tail -5
# Force image pull to ensure latest image is used during testing
kubectl patch deployment network-policy-generator-controller-manager -n "$NAMESPACE" \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"manager","imagePullPolicy":"Always"}]}}}}' 2>/dev/null || true

# Wait for rollout to complete (prevents 2 ReplicaSets / 2 pods)
log_info "Waiting for rollout to complete..."
kubectl rollout status deployment/network-policy-generator-controller-manager \
  -n "$NAMESPACE" --timeout=180s 2>/dev/null || true

# Wait until only 1 Running pod remains (old pod may still be terminating)
log_info "Waiting for old pods to terminate..."
for i in $(seq 1 30); do
  POD_COUNT=$(kubectl get pods -l control-plane=controller-manager -n "$NAMESPACE" \
    --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$POD_COUNT" -le 1 ]]; then break; fi
  sleep 2
done

# Wait for controller pod to be ready
log_info "Waiting for controller to be ready..."
if ! kubectl wait --for=condition=ready pod -l control-plane=controller-manager \
  -n "$NAMESPACE" --timeout=60s; then
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
if should_test "kubernetes"; then
  echo ""
  log_info "--- Kubernetes NetworkPolicy Tests ---"

  # Test A: Deny Policy
  log_info "[Test A] Kubernetes Deny Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-deny.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
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
  if wait_for_phase test-ns1 "Enforcing"; then
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
  if wait_for_phase test-ns1 "Learning"; then
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

  # Test D-1: Pod Selector Policy
  log_info "[Test D-1] Kubernetes Pod Selector Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-pod-selector.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test D-1: CR created with Enforcing phase"
  else
    log_fail "Test D-1: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test D-1: NetworkPolicy generated"
    POD_SELECTOR=$(kubectl get networkpolicy -n test-ns1 -o jsonpath='{.items[0].spec.podSelector.matchLabels}' 2>/dev/null)
    if echo "$POD_SELECTOR" | grep -q "web"; then
      log_pass "Test D-1: podSelector labels applied correctly"
    else
      log_fail "Test D-1: podSelector labels not found"
    fi
  else
    log_fail "Test D-1: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test D-2: CIDR Rules Policy
  log_info "[Test D-2] Kubernetes CIDR Rules Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cidr-rules.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test D-2: CR created with Enforcing phase"
  else
    log_fail "Test D-2: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test D-2: NetworkPolicy generated"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    if echo "$NP_JSON" | grep -q "10.0.0.0/8"; then
      log_pass "Test D-2: Egress CIDR rule (10.0.0.0/8) found"
    else
      log_fail "Test D-2: Egress CIDR rule not found"
    fi
    if echo "$NP_JSON" | grep -q "192.168.1.0/24"; then
      log_pass "Test D-2: Ingress CIDR rule (192.168.1.0/24) found"
    else
      log_fail "Test D-2: Ingress CIDR rule not found"
    fi
    if echo "$NP_JSON" | grep -q "192.168.1.200/32"; then
      log_pass "Test D-2: CIDR except rule found"
    else
      log_fail "Test D-2: CIDR except rule not found"
    fi
  else
    log_fail "Test D-2: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test D-3: Named Port Policy
  log_info "[Test D-3] Kubernetes Named Port Policy"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-named-port.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test D-3: CR created with Enforcing phase"
  else
    log_fail "Test D-3: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test D-3: NetworkPolicy generated"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    if echo "$NP_JSON" | grep -q '"http"'; then
      log_pass "Test D-3: Named port 'http' found"
    else
      log_fail "Test D-3: Named port 'http' not found"
    fi
    if echo "$NP_JSON" | grep -q '"grpc"'; then
      log_pass "Test D-3: Named port 'grpc' found"
    else
      log_fail "Test D-3: Named port 'grpc' not found"
    fi
  else
    log_fail "Test D-3: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test D-4: Dry Run Mode
  log_info "[Test D-4] Kubernetes Dry Run Mode"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-dry-run.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test D-4: CR created with Enforcing phase"
  else
    log_fail "Test D-4: CR not in Enforcing phase"
  fi
  # In dry-run mode, no NetworkPolicy should be created
  if ! kubectl get networkpolicies -n test-ns1 2>/dev/null | grep -q "generated"; then
    log_pass "Test D-4: No NetworkPolicy created (dry-run mode)"
  else
    log_fail "Test D-4: NetworkPolicy unexpectedly created in dry-run mode"
  fi
  # Verify generated policies are stored in status
  GENERATED=$(kubectl get networkpolicygenerators -n test-ns1 -o jsonpath='{.items[0].status.generatedPolicies}' 2>/dev/null)
  if [[ -n "$GENERATED" && "$GENERATED" != "[]" ]]; then
    log_pass "Test D-4: Generated policies stored in status"
  else
    log_fail "Test D-4: Generated policies not found in status"
  fi
  cleanup_cr
  sleep 2

  # Test D-5: Full Features (combined)
  log_info "[Test D-5] Kubernetes Full Features (pod-selector + CIDR + named-port + diff)"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-full-features.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test D-5: CR created with Enforcing phase"
  else
    log_fail "Test D-5: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test D-5: NetworkPolicy generated"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    if echo "$NP_JSON" | grep -q "payment-service"; then
      log_pass "Test D-5: podSelector applied"
    else
      log_fail "Test D-5: podSelector not found"
    fi
    if echo "$NP_JSON" | grep -q "10.0.0.0/8"; then
      log_pass "Test D-5: CIDR rule applied"
    else
      log_fail "Test D-5: CIDR rule not found"
    fi
    if echo "$NP_JSON" | grep -q '"metrics"'; then
      log_pass "Test D-5: Named port applied"
    else
      log_fail "Test D-5: Named port not found"
    fi
    # Check policy diff in status
    DIFF=$(kubectl get networkpolicygenerators -n test-ns1 -o jsonpath='{.items[0].status.policyDiff}' 2>/dev/null)
    if [[ -n "$DIFF" && "$DIFF" != "[]" ]]; then
      log_pass "Test D-5: Policy diff tracked in status"
    else
      log_fail "Test D-5: Policy diff not found in status"
    fi
    # Check applied count
    COUNT=$(kubectl get networkpolicygenerators -n test-ns1 -o jsonpath='{.items[0].status.appliedPoliciesCount}' 2>/dev/null)
    if [[ "$COUNT" -gt 0 ]]; then
      log_pass "Test D-5: Applied policies count: ${COUNT}"
    else
      log_fail "Test D-5: Applied policies count is 0"
    fi
  else
    log_fail "Test D-5: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test D-6: Event Recording
  log_info "[Test D-6] Event Recording Verification"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-deny.yaml" -n test-ns1
  sleep 5
  EVENTS=$(kubectl get events -n test-ns1 --field-selector involvedObject.kind=NetworkPolicyGenerator 2>/dev/null)
  if echo "$EVENTS" | grep -qi "PolicyApplied\|Normal"; then
    log_pass "Test D-6: Events recorded for NetworkPolicyGenerator"
  else
    log_fail "Test D-6: No events found for NetworkPolicyGenerator"
  fi
  cleanup_cr
  sleep 2

  # Test D-7: Prometheus Metrics
  log_info "[Test D-7] Prometheus Metrics Verification"
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
      log_info "Test D-7: No metrics response received (debug: token=${TOKEN:+set}, pod=${METRICS_POD})"
    fi

    if echo "$METRICS" | grep -q "npg_reconcile_total"; then
      log_pass "Test D-7: npg_reconcile_total metric found"
    else
      log_fail "Test D-7: npg_reconcile_total metric not found"
    fi
    if echo "$METRICS" | grep -q "npg_reconcile_duration_seconds"; then
      log_pass "Test D-7: npg_reconcile_duration_seconds metric found"
    else
      log_fail "Test D-7: npg_reconcile_duration_seconds metric not found"
    fi
    if echo "$METRICS" | grep -q "npg_policy_operations_total"; then
      log_pass "Test D-7: npg_policy_operations_total metric found"
    else
      log_fail "Test D-7: npg_policy_operations_total metric not found"
    fi
  else
    log_skip "Test D-7: Metrics service not found, skipping metrics test"
  fi

  # Test D: Multi-Namespace
  log_info "[Test D] Multi-Namespace Policy (test-policy.yaml)"
  kubectl apply -f "${SAMPLES_DIR}/test-policy.yaml"
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test D: test-ns1 CR in Enforcing phase"
  else
    log_fail "Test D: test-ns1 CR not in Enforcing phase"
  fi
  if wait_for_phase test-ns2 "Enforcing"; then
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
if should_test "cilium"; then
  echo ""
  if check_cilium; then
    log_info "--- Cilium NetworkPolicy Tests ---"

    # Test E: Cilium Deny Policy
    log_info "[Test E] Cilium Deny Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-cilium-deny.yaml" -n test-ns1
    if wait_for_phase test-ns1 "Enforcing"; then
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
    if wait_for_phase test-ns1 "Enforcing"; then
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
# Calico Engine Tests
# ============================================================
if should_test "calico"; then
  echo ""
  if check_calico; then
    log_info "--- Calico NetworkPolicy Tests ---"

    # Test G: Calico Deny Policy
    log_info "[Test G] Calico Deny Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-calico-deny.yaml" -n test-ns1
    if wait_for_phase test-ns1 "Enforcing"; then
      log_pass "Test G: CR created with Enforcing phase"
    else
      log_fail "Test G: CR not in Enforcing phase"
    fi
    if wait_for_resource "networkpolicies.crd.projectcalico.org" "test-ns1" 10; then
      log_pass "Test G: Calico NetworkPolicy generated"
    else
      log_fail "Test G: Calico NetworkPolicy not generated"
    fi
    cleanup_cr
    sleep 2
    if ! kubectl get networkpolicies.crd.projectcalico.org -n test-ns1 2>/dev/null | grep -q "generated"; then
      log_pass "Test G: Calico NetworkPolicy cleaned up (finalizer)"
    else
      log_fail "Test G: Calico NetworkPolicy not cleaned up"
    fi

    # Test H: Calico Allow Policy
    log_info "[Test H] Calico Allow Policy"
    kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-calico-allow.yaml" -n test-ns1
    if wait_for_phase test-ns1 "Enforcing"; then
      log_pass "Test H: CR created with Enforcing phase"
    else
      log_fail "Test H: CR not in Enforcing phase"
    fi
    if wait_for_resource "networkpolicies.crd.projectcalico.org" "test-ns1" 10; then
      log_pass "Test H: Calico NetworkPolicy generated"
    else
      log_fail "Test H: Calico NetworkPolicy not generated"
    fi
    cleanup_cr
  else
    log_skip "Calico CRD not found, skipping Calico tests"
  fi
fi

# ============================================================
# Policy Template Tests (Kubernetes Engine)
# ============================================================
if should_test "kubernetes"; then
  echo ""
  log_info "--- Policy Template Tests ---"

  # Test I: Web-App Template
  log_info "[Test I] Web-App Template"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-template-web-app.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test I: CR created with Enforcing phase"
  else
    log_fail "Test I: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test I: NetworkPolicy generated from web-app template"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    # web-app template should add port 80 and 443 ingress rules
    if echo "$NP_JSON" | grep -q '"80"\|80'; then
      log_pass "Test I: Port 80 ingress rule found (from template)"
    else
      log_fail "Test I: Port 80 ingress rule not found"
    fi
  else
    log_fail "Test I: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2

  # Test J: Database Template
  log_info "[Test J] Database Template"
  kubectl apply -f "${SAMPLES_DIR}/security_v1_networkpolicygenerator-template-database.yaml" -n test-ns1
  if wait_for_phase test-ns1 "Enforcing"; then
    log_pass "Test J: CR created with Enforcing phase"
  else
    log_fail "Test J: CR not in Enforcing phase"
  fi
  if wait_for_resource "networkpolicies" "test-ns1" 10; then
    log_pass "Test J: NetworkPolicy generated from database template"
    NP_JSON=$(kubectl get networkpolicy -n test-ns1 -o json 2>/dev/null)
    # database template should have DB port rules (5432 for postgres)
    if echo "$NP_JSON" | grep -q "5432"; then
      log_pass "Test J: PostgreSQL port 5432 rule found (from template)"
    else
      log_fail "Test J: PostgreSQL port 5432 rule not found"
    fi
  else
    log_fail "Test J: NetworkPolicy not generated"
  fi
  cleanup_cr
  sleep 2
fi

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
