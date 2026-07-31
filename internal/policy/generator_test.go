package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestGenerator(t *testing.T) {
	generator := NewGenerator()

	t.Run("Generate Basic NetworkPolicy", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
				UID:       types.UID("test-uid"),
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: PolicyTypeDeny,
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.Equal(t, "test-policy-generated", policies[0].Name)
		assert.Equal(t, nsTest, policies[0].Namespace)
	})

	t.Run("Generate Policy with Allow Type and Denied Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type:             PolicyTypeAllow,
					DeniedNamespaces: []string{"test-ns1", "test-ns2"},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		require.NoError(t, err)
		require.Len(t, policies, 2)

		for i, policy := range policies {
			assert.Equal(t, spec.Spec.Policy.DeniedNamespaces[i], policy.Namespace)
			require.NotEmpty(t, policy.Spec.Ingress)
			require.Len(t, policy.Spec.Ingress, 1)
			require.NotNil(t, policy.Spec.Ingress[0].From)
			require.Len(t, policy.Spec.Ingress[0].From, 1)

			fromRule := policy.Spec.Ingress[0].From[0]
			require.NotNil(t, fromRule.NamespaceSelector)
			require.NotEmpty(t, fromRule.NamespaceSelector.MatchExpressions)

			matchExpression := fromRule.NamespaceSelector.MatchExpressions[0]
			assert.Equal(t, "kubernetes.io/metadata.name", matchExpression.Key)
			assert.Equal(t, metav1.LabelSelectorOpNotIn, matchExpression.Operator)
			assert.ElementsMatch(t, spec.Spec.Policy.DeniedNamespaces, matchExpression.Values)
		}
	})

	t.Run("Generate Policy with Global Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: PolicyTypeDeny,
				},
				GlobalRules: []securityv1.GlobalRule{
					{
						Direction: DirectionIngress,
						Protocol:  ProtocolTCP,
						Port:      80,
					},
					{
						Direction: DirectionEgress,
						Protocol:  ProtocolTCP,
						Port:      443,
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]
		assert.NotNil(t, policy)
		assert.Len(t, policy.Spec.Ingress, 1)
		// 1 global egress rule + 1 DNS egress rule
		assert.Len(t, policy.Spec.Egress, 2)
	})

	t.Run("Generate Policy with Allowed Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type:              PolicyTypeDeny,
					AllowedNamespaces: []string{nsAllowed1, nsAllowed2},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]
		assert.Equal(t, spec.Namespace, policy.Namespace)
		assert.Len(t, policy.Spec.Ingress[0].From, 2)
		assert.Len(t, policy.Spec.Egress[0].To, 2)
	})

	t.Run("Generate Policy with Pod Selector", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: PolicyTypeDeny,
					PodSelector: map[string]string{
						labelApp:  labelValueWeb,
						labelTier: labelValueFrontend,
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]
		assert.Equal(t, labelValueWeb, policy.Spec.PodSelector.MatchLabels[labelApp])
		assert.Equal(t, labelValueFrontend, policy.Spec.PodSelector.MatchLabels[labelTier])
	})

	t.Run("Generate Policy without Pod Selector defaults to empty", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: PolicyTypeDeny,
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Empty(t, policies[0].Spec.PodSelector.MatchLabels)
	})

	t.Run("Generate Policy with CIDR Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: PolicyTypeDeny,
				},
				CIDRRules: []securityv1.CIDRRule{
					{
						CIDR:      cidr10Slash8,
						Direction: DirectionEgress,
					},
					{
						CIDR:      cidr192Slash24,
						Except:    []string{cidrHost192},
						Direction: DirectionIngress,
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]

		// 1 DNS egress + 1 CIDR egress
		require.Len(t, policy.Spec.Egress, 2)
		assert.Equal(t, cidr10Slash8, policy.Spec.Egress[1].To[0].IPBlock.CIDR)

		// 1 CIDR ingress
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Equal(t, cidr192Slash24, policy.Spec.Ingress[0].From[0].IPBlock.CIDR)
		assert.Equal(t, []string{cidrHost192}, policy.Spec.Ingress[0].From[0].IPBlock.Except)
	})

	t.Run("Generate Policy with Named Port", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: PolicyTypeDeny,
				},
				GlobalRules: []securityv1.GlobalRule{
					{
						Direction: DirectionIngress,
						Protocol:  ProtocolTCP,
						NamedPort: namedPortHTTP,
					},
					{
						Direction: DirectionEgress,
						Protocol:  ProtocolTCP,
						NamedPort: "grpc",
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]

		require.Len(t, policy.Spec.Ingress, 1)
		assert.Equal(t, namedPortHTTP, policy.Spec.Ingress[0].Ports[0].Port.StrVal)

		// 1 DNS egress + 1 named port egress
		require.Len(t, policy.Spec.Egress, 2)
		assert.Equal(t, "grpc", policy.Spec.Egress[1].Ports[0].Port.StrVal)
	})

	t.Run("Generate Allow Policy with Pod Selector", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameTestPolicy,
				Namespace: nsTest,
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type:             PolicyTypeAllow,
					DeniedNamespaces: []string{"denied-ns"},
					PodSelector: map[string]string{
						labelApp: "api",
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		assert.Equal(t, "api", policies[0].Spec.PodSelector.MatchLabels[labelApp])
		assert.Equal(t, "denied-ns", policies[0].Namespace)
	})
}
