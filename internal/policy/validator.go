package policy

import (
	"fmt"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// Validator handles NetworkPolicy validation
type Validator struct{}

// NewValidator creates a new NetworkPolicy validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidatePolicy checks if the generated NetworkPolicy is valid
func (v *Validator) ValidatePolicy(policy *networkingv1.NetworkPolicy, generator *securityv1.NetworkPolicyGenerator) error {
	if policy.Name == "" {
		return fmt.Errorf("network policy name cannot be empty")
	}

	if policy.Namespace != generator.Namespace {
		return fmt.Errorf("network policy namespace must match generator namespace")
	}

	// Validate namespace configurations
	if err := v.validateNamespaceConfigs(generator); err != nil {
		return err
	}

	return v.validateRules(policy)
}

// validateRules checks if the policy rules are valid
func (v *Validator) validateRules(policy *networkingv1.NetworkPolicy) error {
	// Validate ingress rules
	for i, rule := range policy.Spec.Ingress {
		if err := v.validatePorts(rule.Ports); err != nil {
			return fmt.Errorf("invalid ingress rule %d: %w", i, err)
		}
	}

	// Validate egress rules
	for i, rule := range policy.Spec.Egress {
		if err := v.validatePorts(rule.Ports); err != nil {
			return fmt.Errorf("invalid egress rule %d: %w", i, err)
		}
	}

	return nil
}

// validatePorts checks if the port specifications are valid
func (v *Validator) validatePorts(ports []networkingv1.NetworkPolicyPort) error {
	for i, port := range ports {
		if port.Port != nil {
			portVal := port.Port.IntVal
			if portVal <= 0 || portVal > 65535 {
				return fmt.Errorf("port %d is out of valid range (1-65535)", portVal)
			}
		}

		if port.Protocol != nil {
			protocol := *port.Protocol
			if protocol != "TCP" && protocol != "UDP" && protocol != "SCTP" {
				return fmt.Errorf("invalid protocol %s for port %d", protocol, i)
			}
		}
	}
	return nil
}

func (v *Validator) validateNamespaceConfigs(generator *securityv1.NetworkPolicyGenerator) error {
	// Check for namespace overlap
	if generator.Spec.Policy.Type == "deny" {
		deniedSet := make(map[string]bool)
		for _, ns := range generator.Spec.Policy.DeniedNamespaces {
			deniedSet[ns] = true
		}

		for _, ns := range generator.Spec.Policy.AllowedNamespaces {
			if deniedSet[ns] {
				return fmt.Errorf("namespace %s cannot be both allowed and denied", ns)
			}
		}
	}

	return nil
}
