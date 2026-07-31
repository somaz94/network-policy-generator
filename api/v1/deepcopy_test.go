package v1

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// mutatedValue is written into an original object's shared reference fields to
// prove DeepCopy produced an independent copy: the copy must never observe it.
const mutatedValue = "changed"

func TestCIDRRule_DeepCopy(t *testing.T) {
	in := &CIDRRule{
		CIDR:      cidr10Slash8,
		Except:    []string{cidr10Slash16, "10.2.0.0/16"},
		Direction: directionEgress,
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("DeepCopy mismatch: got %+v, want %+v", out, in)
	}
	// Mutate original's Except slice to verify independence
	in.Except[0] = mutatedValue
	if out.Except[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy Except slice")
	}
}

func TestCIDRRule_DeepCopy_Nil(t *testing.T) {
	var in *CIDRRule
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestCIDRRule_DeepCopy_NoExcept(t *testing.T) {
	in := &CIDRRule{CIDR: cidr10Slash8, Direction: directionIngress}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("DeepCopy mismatch: got %+v, want %+v", out, in)
	}
	if out.Except != nil {
		t.Fatal("Except should be nil when source is nil")
	}
}

func TestGlobalRule_DeepCopy(t *testing.T) {
	in := &GlobalRule{Type: policyTypeAllow, Port: 80, Protocol: protocolTCP, Direction: directionIngress}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("DeepCopy mismatch: got %+v, want %+v", out, in)
	}
}

func TestGlobalRule_DeepCopy_Nil(t *testing.T) {
	var in *GlobalRule
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestNetworkPolicyGenerator_DeepCopy(t *testing.T) {
	in := &NetworkPolicyGenerator{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: nsDefault},
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
			GlobalRules: []GlobalRule{
				{Type: policyTypeAllow, Port: 443, Protocol: protocolTCP, Direction: directionIngress},
			},
			CIDRRules: []CIDRRule{
				{CIDR: cidr10Slash8, Except: []string{cidr10Slash16}, Direction: directionEgress},
			},
		},
		Status: NetworkPolicyGeneratorStatus{
			Phase:             "Enforcing",
			ObservedTraffic:   []TrafficFlow{{SourceNamespace: "a", DestNamespace: "b", Port: 80}},
			GeneratedPolicies: []string{"policy1"},
		},
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("DeepCopy mismatch")
	}
	// Verify independence
	in.Spec.Policy.AllowedNamespaces[0] = mutatedValue
	if out.Spec.Policy.AllowedNamespaces[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy spec")
	}
}

func TestNetworkPolicyGenerator_DeepCopy_Nil(t *testing.T) {
	var in *NetworkPolicyGenerator
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestNetworkPolicyGenerator_DeepCopyObject(t *testing.T) {
	in := &NetworkPolicyGenerator{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	obj := in.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}
	out, ok := obj.(*NetworkPolicyGenerator)
	if !ok {
		t.Fatal("DeepCopyObject did not return *NetworkPolicyGenerator")
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopyObject mismatch")
	}
}

func TestNetworkPolicyGeneratorList_DeepCopy(t *testing.T) {
	in := &NetworkPolicyGeneratorList{
		Items: []NetworkPolicyGenerator{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "item1"},
				Spec: NetworkPolicyGeneratorSpec{
					Mode:   modeEnforcing,
					Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
				},
			},
		},
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
	// Verify independence
	in.Items[0].Spec.Policy.AllowedNamespaces[0] = mutatedValue
	if out.Items[0].Spec.Policy.AllowedNamespaces[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy items")
	}
}

func TestNetworkPolicyGeneratorList_DeepCopy_Nil(t *testing.T) {
	var in *NetworkPolicyGeneratorList
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestNetworkPolicyGeneratorList_DeepCopyObject(t *testing.T) {
	in := &NetworkPolicyGeneratorList{
		Items: []NetworkPolicyGenerator{
			{ObjectMeta: metav1.ObjectMeta{Name: "item1"}},
		},
	}
	obj := in.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}
	out, ok := obj.(*NetworkPolicyGeneratorList)
	if !ok {
		t.Fatal("DeepCopyObject did not return *NetworkPolicyGeneratorList")
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopyObject mismatch")
	}
}

func TestNetworkPolicyGeneratorSpec_DeepCopy(t *testing.T) {
	in := &NetworkPolicyGeneratorSpec{
		Mode:     modeEnforcing,
		Duration: metav1.Duration{Duration: 5 * time.Minute},
		Policy: PolicyConfig{
			Type:              policyTypeDeny,
			AllowedNamespaces: []string{nsOne, nsTwo},
			DeniedNamespaces:  []string{"ns3"},
			PodSelector:       map[string]string{"app": "web"},
		},
		GlobalRules: []GlobalRule{
			{Type: policyTypeAllow, Port: 80, Protocol: protocolTCP, Direction: directionIngress},
			{Type: policyTypeDeny, NamedPort: "grpc", Protocol: protocolTCP, Direction: directionEgress},
		},
		CIDRRules: []CIDRRule{
			{CIDR: cidr10Slash8, Except: []string{cidr10Slash16}, Direction: directionEgress},
		},
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
	// Verify independence of slices
	in.GlobalRules[0].Port = 9999
	if out.GlobalRules[0].Port == 9999 {
		t.Fatal("DeepCopy did not deep copy GlobalRules")
	}
	in.CIDRRules[0].Except[0] = mutatedValue
	if out.CIDRRules[0].Except[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy CIDRRules Except")
	}
}

func TestNetworkPolicyGeneratorSpec_DeepCopy_Nil(t *testing.T) {
	var in *NetworkPolicyGeneratorSpec
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestNetworkPolicyGeneratorStatus_DeepCopy(t *testing.T) {
	now := metav1.Now()
	in := &NetworkPolicyGeneratorStatus{
		Phase:        "Learning",
		LastAnalyzed: now,
		ObservedTraffic: []TrafficFlow{
			{SourceNamespace: "a", DestNamespace: "b", Port: 80, Protocol: protocolTCP},
		},
		SuggestedNamespaces: []string{nsOne, nsTwo},
		SuggestedRules: []SuggestedRule{
			{Port: 443, Protocol: protocolTCP, Direction: directionIngress, Count: 5},
		},
		GeneratedPolicies: []string{"policy-yaml-1", "policy-yaml-2"},
		PolicyDiff: []PolicyDiffEntry{
			{PolicyName: "pol1", Namespace: nsDefault, Action: "Created", Timestamp: now},
		},
		AppliedPoliciesCount: 3,
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
	// Verify independence
	in.ObservedTraffic[0].Port = 9999
	if out.ObservedTraffic[0].Port == 9999 {
		t.Fatal("DeepCopy did not deep copy ObservedTraffic")
	}
	in.SuggestedNamespaces[0] = mutatedValue
	if out.SuggestedNamespaces[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy SuggestedNamespaces")
	}
	in.SuggestedRules[0].Port = 1111
	if out.SuggestedRules[0].Port == 1111 {
		t.Fatal("DeepCopy did not deep copy SuggestedRules")
	}
	in.GeneratedPolicies[0] = mutatedValue
	if out.GeneratedPolicies[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy GeneratedPolicies")
	}
	in.PolicyDiff[0].Action = mutatedValue
	if out.PolicyDiff[0].Action == mutatedValue {
		t.Fatal("DeepCopy did not deep copy PolicyDiff")
	}
}

func TestNetworkPolicyGeneratorStatus_DeepCopy_Nil(t *testing.T) {
	var in *NetworkPolicyGeneratorStatus
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestPolicyConfig_DeepCopy(t *testing.T) {
	in := &PolicyConfig{
		Type:              policyTypeDeny,
		AllowedNamespaces: []string{nsOne, nsTwo},
		DeniedNamespaces:  []string{"ns3"},
		PodSelector:       map[string]string{"app": "web", "tier": "frontend"},
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
	// Verify independence
	in.AllowedNamespaces[0] = mutatedValue
	if out.AllowedNamespaces[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy AllowedNamespaces")
	}
	in.DeniedNamespaces[0] = mutatedValue
	if out.DeniedNamespaces[0] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy DeniedNamespaces")
	}
	in.PodSelector["app"] = mutatedValue
	if out.PodSelector["app"] == mutatedValue {
		t.Fatal("DeepCopy did not deep copy PodSelector")
	}
}

func TestPolicyConfig_DeepCopy_Nil(t *testing.T) {
	var in *PolicyConfig
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestPolicyDiffEntry_DeepCopy(t *testing.T) {
	now := metav1.Now()
	in := &PolicyDiffEntry{
		PolicyName: "pol1",
		Namespace:  nsDefault,
		Action:     "Created",
		Timestamp:  now,
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
}

func TestPolicyDiffEntry_DeepCopy_Nil(t *testing.T) {
	var in *PolicyDiffEntry
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestSuggestedRule_DeepCopy(t *testing.T) {
	in := &SuggestedRule{Port: 443, Protocol: protocolTCP, Direction: directionIngress, Count: 10}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
}

func TestSuggestedRule_DeepCopy_Nil(t *testing.T) {
	var in *SuggestedRule
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}

func TestTrafficFlow_DeepCopy(t *testing.T) {
	in := &TrafficFlow{
		SourceNamespace: "src-ns",
		SourcePod:       "src-pod",
		DestNamespace:   "dst-ns",
		DestPod:         "dst-pod",
		Protocol:        protocolTCP,
		Port:            8080,
	}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) {
		t.Fatal("DeepCopy mismatch")
	}
}

func TestTrafficFlow_DeepCopy_Nil(t *testing.T) {
	var in *TrafficFlow
	if in.DeepCopy() != nil {
		t.Fatal("expected nil for nil receiver")
	}
}
