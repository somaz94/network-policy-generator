package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestValidator(t *testing.T) {
	validator := NewValidator()

	t.Run("Validate Valid Policy", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: (*v1.Protocol)(ptr.To("TCP")),
								Port:     ptr.To(intstr.FromInt32(80)),
							},
						},
					},
				},
			},
		}

		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}

		err := validator.ValidatePolicy(policy, generator)
		assert.NoError(t, err)
	})

	t.Run("Validate Namespace Configurations", func(t *testing.T) {
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type:              "deny",
					AllowedNamespaces: []string{"ns1", "ns2"},
					DeniedNamespaces:  []string{"ns1", "ns3"}, // Overlap with allowed
				},
			},
		}

		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
		}

		err := validator.ValidatePolicy(policy, generator)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "namespace ns1 cannot be both allowed and denied")
	})

	t.Run("Validate Invalid Port", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: (*v1.Protocol)(ptr.To("TCP")),
								Port:     ptr.To(intstr.FromInt32(0)), // Invalid port
							},
						},
					},
				},
			},
		}

		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}

		err := validator.ValidatePolicy(policy, generator)
		assert.Error(t, err)
	})

	t.Run("Validate Empty Policy Name", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "",
				Namespace: "test-namespace",
			},
		}
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}
		err := validator.ValidatePolicy(policy, generator)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("Validate Namespace Mismatch for Deny Type", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "different-namespace",
			},
		}
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
			},
		}
		err := validator.ValidatePolicy(policy, generator)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "namespace must match")
	})

	t.Run("Validate Allow Type Allows Different Namespace", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "denied-ns",
			},
		}
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: "allow",
				},
			},
		}
		err := validator.ValidatePolicy(policy, generator)
		assert.NoError(t, err)
	})

	t.Run("Validate Invalid Egress Port", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: (*v1.Protocol)(ptr.To("TCP")),
								Port:     ptr.To(intstr.FromInt32(70000)), // Out of range
							},
						},
					},
				},
			},
		}
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}
		err := validator.ValidatePolicy(policy, generator)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid egress rule")
	})

	t.Run("Validate SCTP Protocol Is Valid", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: (*v1.Protocol)(ptr.To("SCTP")),
								Port:     ptr.To(intstr.FromInt32(80)),
							},
						},
					},
				},
			},
		}
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}
		err := validator.ValidatePolicy(policy, generator)
		assert.NoError(t, err)
	})

	t.Run("Validate No Namespace Overlap for Allow Type", func(t *testing.T) {
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type:              "allow",
					AllowedNamespaces: []string{"ns1"},
					DeniedNamespaces:  []string{"ns1"},
				},
			},
		}
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
		}
		// allow type skips namespace overlap check
		err := validator.ValidatePolicy(policy, generator)
		assert.NoError(t, err)
	})

	t.Run("Validate Invalid Protocol", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: (*v1.Protocol)(ptr.To("INVALID")), // Invalid protocol
								Port:     ptr.To(intstr.FromInt32(80)),
							},
						},
					},
				},
			},
		}

		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}

		err := validator.ValidatePolicy(policy, generator)
		assert.Error(t, err)
	})

	t.Run("Validate Named Port Is Valid", func(t *testing.T) {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: (*v1.Protocol)(ptr.To("TCP")),
								Port:     ptr.To(intstr.FromString("http")),
							},
						},
					},
				},
			},
		}
		generator := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
			},
		}
		err := validator.ValidatePolicy(policy, generator)
		assert.NoError(t, err)
	})
}

func TestValidateGlobalRules(t *testing.T) {
	validator := NewValidator()

	t.Run("Valid Numeric Port", func(t *testing.T) {
		rules := []securityv1.GlobalRule{
			{Port: 80, Protocol: "TCP", Direction: "ingress"},
		}
		err := validator.ValidateGlobalRules(rules)
		assert.NoError(t, err)
	})

	t.Run("Valid Named Port", func(t *testing.T) {
		rules := []securityv1.GlobalRule{
			{NamedPort: "http", Protocol: "TCP", Direction: "ingress"},
		}
		err := validator.ValidateGlobalRules(rules)
		assert.NoError(t, err)
	})

	t.Run("Error When Neither Port Nor NamedPort", func(t *testing.T) {
		rules := []securityv1.GlobalRule{
			{Protocol: "TCP", Direction: "ingress"},
		}
		err := validator.ValidateGlobalRules(rules)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either port or namedPort must be specified")
	})

	t.Run("Error When Both Port And NamedPort", func(t *testing.T) {
		rules := []securityv1.GlobalRule{
			{Port: 80, NamedPort: "http", Protocol: "TCP", Direction: "ingress"},
		}
		err := validator.ValidateGlobalRules(rules)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})
}

func TestValidateCIDRRules(t *testing.T) {
	validator := NewValidator()

	t.Run("Valid CIDR Rules", func(t *testing.T) {
		rules := []securityv1.CIDRRule{
			{CIDR: "10.0.0.0/8", Direction: "egress"},
			{CIDR: "192.168.1.0/24", Except: []string{"192.168.1.100/32"}, Direction: "ingress"},
		}
		err := validator.ValidateCIDRRules(rules)
		assert.NoError(t, err)
	})

	t.Run("Invalid CIDR", func(t *testing.T) {
		rules := []securityv1.CIDRRule{
			{CIDR: "not-a-cidr", Direction: "egress"},
		}
		err := validator.ValidateCIDRRules(rules)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CIDR")
	})

	t.Run("Invalid Except CIDR", func(t *testing.T) {
		rules := []securityv1.CIDRRule{
			{CIDR: "10.0.0.0/8", Except: []string{"invalid"}, Direction: "egress"},
		}
		err := validator.ValidateCIDRRules(rules)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "except")
	})

	t.Run("Invalid Direction", func(t *testing.T) {
		rules := []securityv1.CIDRRule{
			{CIDR: "10.0.0.0/8", Direction: "invalid"},
		}
		err := validator.ValidateCIDRRules(rules)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "direction must be")
	})

	t.Run("Empty Rules Valid", func(t *testing.T) {
		err := validator.ValidateCIDRRules(nil)
		assert.NoError(t, err)
	})
}
