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
					Traffic: securityv1.TrafficPolicy{
						Ingress: securityv1.DirectionPolicy{
							FollowDefault: true,
						},
						Egress: securityv1.DirectionPolicy{
							FollowDefault: true,
						},
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.Equal(t, "test-policy-generated", policies[0].Name)
		assert.Equal(t, "test-namespace", policies[0].Namespace)
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
					Traffic: securityv1.TrafficPolicy{
						Ingress: securityv1.DirectionPolicy{
							FollowDefault: true,
						},
						Egress: securityv1.DirectionPolicy{
							FollowDefault: true,
						},
					},
				},
				DeniedNamespaces: []string{"test-ns1", "test-ns2"},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		require.NoError(t, err)
		require.Len(t, policies, 2) // Should generate one policy for each denied namespace

		for i, policy := range policies {
			assert.Equal(t, spec.Spec.DeniedNamespaces[i], policy.Namespace)

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
			assert.ElementsMatch(t, spec.Spec.DeniedNamespaces, matchExpression.Values)
		}
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
					Traffic: securityv1.TrafficPolicy{
						Ingress: securityv1.DirectionPolicy{
							FollowDefault: true,
						},
						Egress: securityv1.DirectionPolicy{
							FollowDefault: true,
						},
					},
				},
				AllowedNamespaces: []string{"kube-system", "monitoring"},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]

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
					Traffic: securityv1.GlobalTrafficRules{
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
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]
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
					Traffic: securityv1.GlobalTrafficRules{
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
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]
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
					Traffic: securityv1.GlobalTrafficRules{
						Ingress: []securityv1.GlobalRule{
							{
								Protocol: "TCP",
								Port:     80,
							},
						},
					},
				},
				GlobalDenyRules: &securityv1.GlobalRuleSet{
					Enabled: false,
					Traffic: securityv1.GlobalTrafficRules{
						Ingress: []securityv1.GlobalRule{
							{
								Protocol: "TCP",
								Port:     22,
							},
						},
					},
				},
			},
		}

		policies, err := generator.GenerateNetworkPolicies(spec)
		assert.NoError(t, err)
		require.Len(t, policies, 1)
		policy := policies[0]
		assert.NotNil(t, policy)
		assert.Len(t, policy.Spec.Ingress, 0)
		assert.Len(t, policy.Spec.Egress, 0)
	})
}
