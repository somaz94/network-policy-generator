package v1

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateGenerator_ValidEnforcing(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode: modeEnforcing,
			Policy: PolicyConfig{
				Type:              policyTypeDeny,
				AllowedNamespaces: []string{"kube-system"},
			},
			GlobalRules: []GlobalRule{
				{Type: policyTypeAllow, Port: 80, Protocol: protocolTCP, Direction: directionIngress},
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
			Mode:     modeLearning,
			Duration: metav1.Duration{Duration: 5 * time.Minute},
			Policy: PolicyConfig{
				Type:              policyTypeDeny,
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
			Mode:   valueInvalid,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
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
			Mode:   modeLearning,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
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
			Mode:   modeEnforcing,
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
			Mode:         modeEnforcing,
			PolicyEngine: "unknown-engine",
			Policy:       PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
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
			Mode: modeEnforcing,
			Policy: PolicyConfig{
				Type:              policyTypeDeny,
				AllowedNamespaces: []string{nsOne},
				DeniedNamespaces:  []string{nsOne},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeAllow},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
			GlobalRules: []GlobalRule{
				{Type: policyTypeAllow, Port: 80, NamedPort: "http", Protocol: protocolTCP, Direction: directionIngress},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
			GlobalRules: []GlobalRule{
				{Type: policyTypeAllow, Protocol: protocolTCP, Direction: directionIngress},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
			CIDRRules: []CIDRRule{
				{CIDR: valueInvalid, Direction: directionEgress},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
			CIDRRules: []CIDRRule{
				{CIDR: cidr10Slash8, Except: []string{"bad"}, Direction: directionEgress},
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
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
			CIDRRules: []CIDRRule{
				{CIDR: cidr10Slash8, Direction: "both"},
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
			Mode:   modeEnforcing,
			DryRun: true,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
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
			Mode:         modeEnforcing,
			PolicyEngine: "cilium",
			Policy:       PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	_, err := validateGenerator(gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateGenerator_ValidCalicoEngine(t *testing.T) {
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:         modeEnforcing,
			PolicyEngine: "calico",
			Policy:       PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
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

func TestValidatorCreate_Valid(t *testing.T) {
	v := &networkPolicyGeneratorValidator{}
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	warnings, err := v.ValidateCreate(context.Background(), gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got: %v", warnings)
	}
}

func TestValidatorCreate_Invalid(t *testing.T) {
	v := &networkPolicyGeneratorValidator{}
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   "bad",
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	_, err := v.ValidateCreate(context.Background(), gen)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestValidatorUpdate_Valid(t *testing.T) {
	v := &networkPolicyGeneratorValidator{}
	oldGen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	newGen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne, nsTwo}},
		},
	}
	warnings, err := v.ValidateUpdate(context.Background(), oldGen, newGen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got: %v", warnings)
	}
}

func TestValidatorUpdate_Invalid(t *testing.T) {
	v := &networkPolicyGeneratorValidator{}
	oldGen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	newGen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   valueInvalid,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	_, err := v.ValidateUpdate(context.Background(), oldGen, newGen)
	if err == nil {
		t.Fatal("expected error for invalid mode on update")
	}
}

func TestValidatorDelete(t *testing.T) {
	v := &networkPolicyGeneratorValidator{}
	gen := &NetworkPolicyGenerator{
		Spec: NetworkPolicyGeneratorSpec{
			Mode:   modeEnforcing,
			Policy: PolicyConfig{Type: policyTypeDeny, AllowedNamespaces: []string{nsOne}},
		},
	}
	warnings, err := v.ValidateDelete(context.Background(), gen)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if warnings != nil {
		t.Fatalf("expected nil warnings, got: %v", warnings)
	}
}
