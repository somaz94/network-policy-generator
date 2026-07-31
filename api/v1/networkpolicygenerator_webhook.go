package v1

import (
	"context"
	"fmt"
	"net"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Spec enum values accepted by the validating webhook. These mirror the
// exported constants in internal/policy, which cannot be imported here:
// internal/policy imports this package, so depending on it would create an
// import cycle. Keep both sides in sync when an enum value changes.
const (
	modeLearning  = "learning"
	modeEnforcing = "enforcing"

	policyTypeAllow = "allow"
	policyTypeDeny  = "deny"

	directionIngress = "ingress"
	directionEgress  = "egress"

	protocolTCP = "TCP"
)

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *NetworkPolicyGenerator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&networkPolicyGeneratorValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-security-policy-io-v1-networkpolicygenerator,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.policy.io,resources=networkpolicygenerators,verbs=create;update,versions=v1,name=vnetworkpolicygenerator.kb.io,admissionReviewVersions=v1

// networkPolicyGeneratorValidator implements admission.Validator[*NetworkPolicyGenerator]
type networkPolicyGeneratorValidator struct{}

var _ admission.Validator[*NetworkPolicyGenerator] = &networkPolicyGeneratorValidator{}

// ValidateCreate implements admission.Validator
func (v *networkPolicyGeneratorValidator) ValidateCreate(_ context.Context, gen *NetworkPolicyGenerator) (admission.Warnings, error) {
	return validateGenerator(gen)
}

// ValidateUpdate implements admission.Validator
func (v *networkPolicyGeneratorValidator) ValidateUpdate(_ context.Context, _ *NetworkPolicyGenerator, newGen *NetworkPolicyGenerator) (admission.Warnings, error) {
	return validateGenerator(newGen)
}

// ValidateDelete implements admission.Validator
func (v *networkPolicyGeneratorValidator) ValidateDelete(_ context.Context, _ *NetworkPolicyGenerator) (admission.Warnings, error) {
	return nil, nil
}

// validateGenerator runs the spec validations in order and, once the spec is
// known good, collects the non-fatal warnings. Each check lives in its own
// helper so this entry point stays flat and every rule is testable on its own.
// Any validation error discards the warnings, so warnings are only ever
// computed for a spec that already passed.
func validateGenerator(gen *NetworkPolicyGenerator) (admission.Warnings, error) {
	spec := &gen.Spec

	if err := validateMode(spec); err != nil {
		return nil, err
	}
	if err := validatePolicyType(spec); err != nil {
		return nil, err
	}
	if err := validatePolicyEngine(spec); err != nil {
		return nil, err
	}
	if err := validateNamespaceOverlap(spec); err != nil {
		return nil, err
	}
	if err := validateGlobalRules(spec); err != nil {
		return nil, err
	}
	if err := validateCIDRRules(spec); err != nil {
		return nil, err
	}

	return specWarnings(spec), nil
}

// validateMode checks the mode enum and the duration that learning mode requires.
func validateMode(spec *NetworkPolicyGeneratorSpec) error {
	if spec.Mode != modeLearning && spec.Mode != modeEnforcing {
		return fmt.Errorf("spec.mode must be 'learning' or 'enforcing', got %q", spec.Mode)
	}
	if spec.Mode == modeLearning && spec.Duration.Duration <= 0 {
		return fmt.Errorf("spec.duration is required and must be positive when mode is 'learning'")
	}
	return nil
}

// validatePolicyType checks the policy type enum.
func validatePolicyType(spec *NetworkPolicyGeneratorSpec) error {
	if spec.Policy.Type != policyTypeAllow && spec.Policy.Type != policyTypeDeny {
		return fmt.Errorf("spec.policy.type must be 'allow' or 'deny', got %q", spec.Policy.Type)
	}
	return nil
}

// validatePolicyEngine checks the optional policy engine enum. An empty value
// is allowed and means the default engine.
func validatePolicyEngine(spec *NetworkPolicyGeneratorSpec) error {
	switch spec.PolicyEngine {
	case "", "kubernetes", "cilium", "calico":
		return nil
	default:
		return fmt.Errorf("spec.policyEngine must be 'kubernetes', 'cilium', or 'calico', got %q", spec.PolicyEngine)
	}
}

// validateNamespaceOverlap rejects a namespace listed as both allowed and
// denied. Only deny-type policies consult both lists.
func validateNamespaceOverlap(spec *NetworkPolicyGeneratorSpec) error {
	if spec.Policy.Type != policyTypeDeny {
		return nil
	}
	deniedSet := make(map[string]bool, len(spec.Policy.DeniedNamespaces))
	for _, ns := range spec.Policy.DeniedNamespaces {
		deniedSet[ns] = true
	}
	for _, ns := range spec.Policy.AllowedNamespaces {
		if deniedSet[ns] {
			return fmt.Errorf("namespace %q cannot be both allowed and denied", ns)
		}
	}
	return nil
}

// validateGlobalRules requires exactly one of port / namedPort per rule.
func validateGlobalRules(spec *NetworkPolicyGeneratorSpec) error {
	for i, rule := range spec.GlobalRules {
		if rule.Port == 0 && rule.NamedPort == "" {
			return fmt.Errorf("spec.globalRules[%d]: either port or namedPort must be specified", i)
		}
		if rule.Port != 0 && rule.NamedPort != "" {
			return fmt.Errorf("spec.globalRules[%d]: port and namedPort are mutually exclusive", i)
		}
	}
	return nil
}

// validateCIDRRules checks each CIDR, its exceptions, and the direction enum.
func validateCIDRRules(spec *NetworkPolicyGeneratorSpec) error {
	for i, rule := range spec.CIDRRules {
		if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
			return fmt.Errorf("spec.cidrRules[%d]: invalid CIDR %q: %v", i, rule.CIDR, err)
		}
		for j, except := range rule.Except {
			if _, _, err := net.ParseCIDR(except); err != nil {
				return fmt.Errorf("spec.cidrRules[%d].except[%d]: invalid CIDR %q: %v", i, j, except, err)
			}
		}
		if rule.Direction != directionIngress && rule.Direction != directionEgress {
			return fmt.Errorf("spec.cidrRules[%d]: direction must be 'ingress' or 'egress'", i)
		}
	}
	return nil
}

// specWarnings collects the non-fatal advisories for an already-valid spec.
func specWarnings(spec *NetworkPolicyGeneratorSpec) admission.Warnings {
	var warnings admission.Warnings
	if spec.Policy.Type == policyTypeDeny && len(spec.Policy.AllowedNamespaces) == 0 {
		warnings = append(warnings, "spec.policy.type is 'deny' but no allowedNamespaces specified")
	}
	if spec.Policy.Type == policyTypeAllow && len(spec.Policy.DeniedNamespaces) == 0 {
		warnings = append(warnings, "spec.policy.type is 'allow' but no deniedNamespaces specified")
	}
	if spec.DryRun {
		warnings = append(warnings, "dry-run mode is enabled: policies will not be applied to the cluster")
	}
	return warnings
}
