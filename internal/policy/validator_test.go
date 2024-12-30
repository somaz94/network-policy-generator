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
}
