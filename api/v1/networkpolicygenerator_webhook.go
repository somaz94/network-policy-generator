package v1

import (
	"context"
	"fmt"
	"net"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
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

func validateGenerator(gen *NetworkPolicyGenerator) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Validate mode
	if gen.Spec.Mode != "learning" && gen.Spec.Mode != "enforcing" {
		return nil, fmt.Errorf("spec.mode must be 'learning' or 'enforcing', got %q", gen.Spec.Mode)
	}

	// Validate learning mode requires duration
	if gen.Spec.Mode == "learning" && gen.Spec.Duration.Duration <= 0 {
		return nil, fmt.Errorf("spec.duration is required and must be positive when mode is 'learning'")
	}

	// Validate policy type
	if gen.Spec.Policy.Type != "allow" && gen.Spec.Policy.Type != "deny" {
		return nil, fmt.Errorf("spec.policy.type must be 'allow' or 'deny', got %q", gen.Spec.Policy.Type)
	}

	// Validate policy engine
	if gen.Spec.PolicyEngine != "" && gen.Spec.PolicyEngine != "kubernetes" && gen.Spec.PolicyEngine != "cilium" {
		return nil, fmt.Errorf("spec.policyEngine must be 'kubernetes' or 'cilium', got %q", gen.Spec.PolicyEngine)
	}

	// Validate namespace overlap
	if gen.Spec.Policy.Type == "deny" {
		deniedSet := make(map[string]bool)
		for _, ns := range gen.Spec.Policy.DeniedNamespaces {
			deniedSet[ns] = true
		}
		for _, ns := range gen.Spec.Policy.AllowedNamespaces {
			if deniedSet[ns] {
				return nil, fmt.Errorf("namespace %q cannot be both allowed and denied", ns)
			}
		}
	}

	// Validate deny-type has allowedNamespaces
	if gen.Spec.Policy.Type == "deny" && len(gen.Spec.Policy.AllowedNamespaces) == 0 {
		warnings = append(warnings, "spec.policy.type is 'deny' but no allowedNamespaces specified")
	}

	// Validate allow-type has deniedNamespaces
	if gen.Spec.Policy.Type == "allow" && len(gen.Spec.Policy.DeniedNamespaces) == 0 {
		warnings = append(warnings, "spec.policy.type is 'allow' but no deniedNamespaces specified")
	}

	// Validate global rules
	for i, rule := range gen.Spec.GlobalRules {
		if rule.Port == 0 && rule.NamedPort == "" {
			return nil, fmt.Errorf("spec.globalRules[%d]: either port or namedPort must be specified", i)
		}
		if rule.Port != 0 && rule.NamedPort != "" {
			return nil, fmt.Errorf("spec.globalRules[%d]: port and namedPort are mutually exclusive", i)
		}
	}

	// Validate CIDR rules
	for i, rule := range gen.Spec.CIDRRules {
		if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
			return nil, fmt.Errorf("spec.cidrRules[%d]: invalid CIDR %q: %v", i, rule.CIDR, err)
		}
		for j, except := range rule.Except {
			if _, _, err := net.ParseCIDR(except); err != nil {
				return nil, fmt.Errorf("spec.cidrRules[%d].except[%d]: invalid CIDR %q: %v", i, j, except, err)
			}
		}
		if rule.Direction != "ingress" && rule.Direction != "egress" {
			return nil, fmt.Errorf("spec.cidrRules[%d]: direction must be 'ingress' or 'egress'", i)
		}
	}

	// Dry-run warning
	if gen.Spec.DryRun {
		warnings = append(warnings, "dry-run mode is enabled: policies will not be applied to the cluster")
	}

	return warnings, nil
}
