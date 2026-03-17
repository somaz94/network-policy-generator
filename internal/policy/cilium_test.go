package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestCiliumEngine(t *testing.T) {
	engine := NewCiliumEngine()

	t.Run("EngineName", func(t *testing.T) {
		assert.Equal(t, "cilium", engine.EngineName())
	})

	t.Run("Generate Basic Deny Policy", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
				UID:       types.UID("test-uid"),
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		assert.Equal(t, "test-policy-generated", policy.Name)
		assert.Equal(t, "test-namespace", policy.Namespace)
		assert.Equal(t, "cilium.io/v2", policy.APIVersion)
		assert.Equal(t, "CiliumNetworkPolicy", policy.Kind)
		// Deny all: no ingress/egress rules except DNS
		assert.Empty(t, policy.Spec.Ingress)
		require.Len(t, policy.Spec.Egress, 1) // DNS only
		assert.Equal(t, "kube-dns", policy.Spec.Egress[0].ToEndpoints[0].MatchLabels["k8s:k8s-app"])
	})

	t.Run("Generate Allow Type with Denied Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type:             "allow",
					DeniedNamespaces: []string{"denied-ns1", "denied-ns2"},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 2)

		for i, obj := range objects {
			policy := obj.(*CiliumNetworkPolicy)
			assert.Equal(t, spec.Spec.Policy.DeniedNamespaces[i], policy.Namespace)
			require.NotEmpty(t, policy.Spec.IngressDeny)
			require.NotEmpty(t, policy.Spec.EgressDeny)
			// Should have DNS egress
			require.NotEmpty(t, policy.Spec.Egress)
		}
	})

	t.Run("Generate Deny Type with Allowed Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type:              "deny",
					AllowedNamespaces: []string{"allowed-ns1", "allowed-ns2"},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		assert.Equal(t, "test-namespace", policy.Namespace)
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Len(t, policy.Spec.Ingress[0].FromEndpoints, 2)
		// 1 namespace egress + 1 DNS egress
		require.Len(t, policy.Spec.Egress, 2)
		assert.Len(t, policy.Spec.Egress[0].ToEndpoints, 2)
	})

	t.Run("Generate Policy with Global Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
				GlobalRules: []securityv1.GlobalRule{
					{
						Direction: "ingress",
						Protocol:  "TCP",
						Port:      80,
					},
					{
						Direction: "egress",
						Protocol:  "TCP",
						Port:      443,
					},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		// 1 global ingress rule
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Contains(t, policy.Spec.Ingress[0].FromEntities, "world")
		assert.Equal(t, "80", policy.Spec.Ingress[0].ToPorts[0].Ports[0].Port)
		assert.Equal(t, "TCP", policy.Spec.Ingress[0].ToPorts[0].Ports[0].Protocol)

		// 1 DNS egress + 1 global egress
		require.Len(t, policy.Spec.Egress, 2)
	})

	t.Run("Allow Type with No Denied Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "allow",
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		assert.Empty(t, objects)
	})

	t.Run("Generate Policy with Pod Selector", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
					PodSelector: map[string]string{
						"app":  "web",
						"tier": "frontend",
					},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		assert.Equal(t, "web", policy.Spec.EndpointSelector.MatchLabels["app"])
		assert.Equal(t, "frontend", policy.Spec.EndpointSelector.MatchLabels["tier"])
	})

	t.Run("Generate Policy without Pod Selector defaults to empty", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		assert.Empty(t, policy.Spec.EndpointSelector.MatchLabels)
	})

	t.Run("Generate Policy with CIDR Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
				CIDRRules: []securityv1.CIDRRule{
					{
						CIDR:      "10.0.0.0/8",
						Direction: "egress",
					},
					{
						CIDR:      "192.168.1.0/24",
						Direction: "ingress",
					},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		// 1 DNS egress + 1 CIDR egress
		require.Len(t, policy.Spec.Egress, 2)
		assert.Contains(t, policy.Spec.Egress[1].ToCIDR, "10.0.0.0/8")

		// 1 CIDR ingress
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Contains(t, policy.Spec.Ingress[0].FromCIDR, "192.168.1.0/24")
	})

	t.Run("Generate Policy with Named Port", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "cilium",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
				GlobalRules: []securityv1.GlobalRule{
					{
						Direction: "ingress",
						Protocol:  "TCP",
						NamedPort: "http",
					},
					{
						Direction: "egress",
						Protocol:  "TCP",
						NamedPort: "grpc",
					},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CiliumNetworkPolicy)
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Equal(t, "http", policy.Spec.Ingress[0].ToPorts[0].Ports[0].Port)

		// 1 DNS egress + 1 named port egress
		require.Len(t, policy.Spec.Egress, 2)
		assert.Equal(t, "grpc", policy.Spec.Egress[1].ToPorts[0].Ports[0].Port)
	})
}

func TestCiliumNetworkPolicyDeepCopy(t *testing.T) {
	original := &CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: &CiliumNetworkPolicySpec{
			EndpointSelector: &CiliumEndpointSelector{
				MatchLabels: map[string]string{"app": "test"},
			},
			Ingress: []CiliumIngressRule{{
				FromEntities: []string{"world"},
			}},
			Egress: []CiliumEgressRule{{
				ToEntities: []string{"cluster"},
			}},
		},
	}

	copied := original.DeepCopyObject().(*CiliumNetworkPolicy)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.EndpointSelector.MatchLabels["app"], copied.Spec.EndpointSelector.MatchLabels["app"])

	// Verify deep copy (modifying copy doesn't affect original)
	copied.Spec.EndpointSelector.MatchLabels["app"] = "modified"
	assert.Equal(t, "test", original.Spec.EndpointSelector.MatchLabels["app"])
}

func TestCiliumNetworkPolicyDeepCopyNil(t *testing.T) {
	var policy *CiliumNetworkPolicy
	result := policy.DeepCopyObject()
	assert.Nil(t, result)
}

func TestCiliumNetworkPolicySpecDeepCopyNil(t *testing.T) {
	var spec *CiliumNetworkPolicySpec
	result := spec.DeepCopy()
	assert.Nil(t, result)
}

func TestCiliumEndpointSelectorDeepCopyNil(t *testing.T) {
	var selector *CiliumEndpointSelector
	result := selector.DeepCopy()
	assert.Nil(t, result)
}
