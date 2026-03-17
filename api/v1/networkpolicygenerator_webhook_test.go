package v1

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateGenerator_ValidEnforcing(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode: "enforcing",
			Policy: PolicyConfig{
				Type:              "deny",
				AllowedNamespaces: []string{"kube-system"},
			},
			GlobalRules: []GlobalRule{
				{Type: "allow", Port: 80, Protocol: "TCP", Direction: "ingress"},
			},
		},
	}
	warnings, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got: %v", warnings)
	}
}

func TestValidateGenerator_ValidLearning(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:     "learning",
			Duration: metav1.Duration{Duration: 5 * time.Minute},
			Policy: PolicyConfig{
				Type:              "deny",
				AllowedNamespaces: []string{"kube-system"},
			},
		},
	}
	warnings, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got: %v", warnings)
	}
}

func TestValidateGenerator_InvalidMode(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "invalid",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestValidateGenerator_LearningWithoutDuration(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "learning",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for learning mode without duration")
	}
}

func TestValidateGenerator_InvalidPolicyType(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "block"},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for invalid policy type")
	}
}

func TestValidateGenerator_InvalidEngine(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:         "enforcing",
			PolicyEngine: "unknown-engine",
			Policy:       PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for invalid policy engine")
	}
}

func TestValidateGenerator_NamespaceOverlap(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode: "enforcing",
			Policy: PolicyConfig{
				Type:              "deny",
				AllowedNamespaces: []string{"ns1"},
				DeniedNamespaces:  []string{"ns1"},
			},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for namespace overlap")
	}
}

func TestValidateGenerator_DenyWithoutAllowed_Warning(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "deny"},
		},
	}
	warnings, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got: %d", len(warnings))
	}
}

func TestValidateGenerator_AllowWithoutDenied_Warning(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "allow"},
		},
	}
	warnings, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got: %d", len(warnings))
	}
}

func TestValidateGenerator_GlobalRulePortAndNamedPort(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
			GlobalRules: []GlobalRule{
				{Type: "allow", Port: 80, NamedPort: "http", Protocol: "TCP", Direction: "ingress"},
			},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for port and namedPort both set")
	}
}

func TestValidateGenerator_GlobalRuleNoPort(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
			GlobalRules: []GlobalRule{
				{Type: "allow", Protocol: "TCP", Direction: "ingress"},
			},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for no port specified")
	}
}

func TestValidateGenerator_InvalidCIDR(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
			CIDRRules: []CIDRRule{
				{CIDR: "invalid", Direction: "egress"},
			},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestValidateGenerator_InvalidCIDRExcept(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
			CIDRRules: []CIDRRule{
				{CIDR: "10.0.0.0/8", Except: []string{"bad"}, Direction: "egress"},
			},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for invalid except CIDR")
	}
}

func TestValidateGenerator_InvalidCIDRDirection(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
			CIDRRules: []CIDRRule{
				{CIDR: "10.0.0.0/8", Direction: "both"},
			},
		},
	}
	_, err := validateGenerator(gen)
	if err == nil {
		t.Fatal("expected error for invalid CIDR direction")
	}
}

func TestValidateGenerator_DryRunWarning(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "enforcing",
			DryRun: true,
			Policy: PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
		},
	}
	warnings, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	found := false
	for _, w := range warnings {
		if w == "dry-run mode is enabled: policies will not be applied to the cluster" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected dry-run warning")
	}
}

func TestValidateGenerator_ValidCiliumEngine(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:         "enforcing",
			PolicyEngine: "cilium",
			Policy:       PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns1"}},
		},
	}
	_, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}
