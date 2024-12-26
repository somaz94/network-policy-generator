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
				Name:      "test-policy",
				Namespace: "test-namespace",
				UID:       types.UID("test-uid"),
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				DefaultPolicy: securityv1.DefaultPolicy{
					Type: securityv1.PolicyDeny,
					Ingress: securityv1.DirectionPolicy{
						FollowDefault: true,
					},
					Egress: securityv1.DirectionPolicy{
						FollowDefault: true,
					},
				},
			},
		}

		policy, err := generator.GenerateNetworkPolicy(spec)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
		assert.Equal(t, "test-policy-generated", policy.Name)
		assert.Equal(t, "test-namespace", policy.Namespace)
	})

	t.Run("Generate Policy with Default Allow and Denied Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				DefaultPolicy: securityv1.DefaultPolicy{
					Type: securityv1.PolicyAllow,
					Ingress: securityv1.DirectionPolicy{
						FollowDefault: true,
					},
					Egress: securityv1.DirectionPolicy{
						FollowDefault: true,
					},
				},
				DeniedNamespaces: []string{"test-ns1", "test-ns2"},
			},
		}

		policy, err := generator.GenerateNetworkPolicy(spec)
		require.NoError(t, err)
		require.NotNil(t, policy)

		// Verify Ingress rules
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
		assert.ElementsMatch(t, []string{"test-ns1", "test-ns2"}, matchExpression.Values)

		// Verify Egress rules
		assert.NotEmpty(t, policy.Spec.Egress, "Egress rules should not be empty")
		assert.Len(t, policy.Spec.Egress, 1, "Should have exactly one egress rule")

		egressRule := policy.Spec.Egress[0]
		assert.NotNil(t, egressRule.To, "Egress To should not be nil")
		assert.Len(t, egressRule.To, 1, "Should have exactly one To rule")

		toRule := egressRule.To[0]
		assert.NotNil(t, toRule.NamespaceSelector, "NamespaceSelector should not be nil")
		assert.NotEmpty(t, toRule.NamespaceSelector.MatchExpressions, "MatchExpressions should not be empty")

		matchExpression = toRule.NamespaceSelector.MatchExpressions[0]
		assert.Equal(t, "kubernetes.io/metadata.name", matchExpression.Key)
		assert.Equal(t, metav1.LabelSelectorOpNotIn, matchExpression.Operator)
		assert.ElementsMatch(t, []string{"test-ns1", "test-ns2"}, matchExpression.Values)
	})

	t.Run("Generate Policy with Default Deny and Allowed Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				DefaultPolicy: securityv1.DefaultPolicy{
					Type: securityv1.PolicyDeny,
					Ingress: securityv1.DirectionPolicy{
						FollowDefault: true,
					},
					Egress: securityv1.DirectionPolicy{
						FollowDefault: true,
					},
				},
				AllowedNamespaces: []string{"kube-system", "monitoring"},
			},
		}

		policy, err := generator.GenerateNetworkPolicy(spec)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
		assert.Len(t, policy.Spec.Ingress, 1)
		assert.Len(t, policy.Spec.Egress, 1)

		// Verify allowed namespaces are properly configured
		assert.Len(t, policy.Spec.Ingress[0].From, 2)
		assert.Equal(t, "kube-system",
			policy.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
		assert.Equal(t, "monitoring",
			policy.Spec.Ingress[0].From[1].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
	})

	t.Run("Generate Policy with Global Allow Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				GlobalAllowRules: &securityv1.GlobalRuleSet{
					Enabled: true,
					Ingress: []securityv1.GlobalRule{
						{
							Protocol: "TCP",
							Port:     80,
						},
					},
					Egress: []securityv1.GlobalRule{
						{
							Protocol: "TCP",
							Port:     443,
						},
					},
				},
			},
		}

		policy, err := generator.GenerateNetworkPolicy(spec)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
		assert.Len(t, policy.Spec.Ingress, 1)
		assert.Len(t, policy.Spec.Egress, 1)
	})

	t.Run("Generate Policy with Global Deny Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				GlobalDenyRules: &securityv1.GlobalRuleSet{
					Enabled: true,
					Ingress: []securityv1.GlobalRule{
						{
							Protocol: "TCP",
							Port:     22,
						},
					},
					Egress: []securityv1.GlobalRule{
						{
							Protocol: "TCP",
							Port:     25,
						},
					},
				},
			},
		}

		policy, err := generator.GenerateNetworkPolicy(spec)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
		assert.Len(t, policy.Spec.Ingress, 1)
		assert.Len(t, policy.Spec.Egress, 1)
	})

	t.Run("Generate Policy with Disabled Global Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				GlobalAllowRules: &securityv1.GlobalRuleSet{
					Enabled: false,
					Ingress: []securityv1.GlobalRule{
						{
							Protocol: "TCP",
							Port:     80,
						},
					},
				},
				GlobalDenyRules: &securityv1.GlobalRuleSet{
					Enabled: false,
					Ingress: []securityv1.GlobalRule{
						{
							Protocol: "TCP",
							Port:     22,
						},
					},
				},
			},
		}

		policy, err := generator.GenerateNetworkPolicy(spec)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
		assert.Len(t, policy.Spec.Ingress, 0)
		assert.Len(t, policy.Spec.Egress, 0)
	})
}
