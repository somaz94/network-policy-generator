package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestCalicoEngine(t *testing.T) {
	engine := NewCalicoEngine()

	t.Run("EngineName", func(t *testing.T) {
		assert.Equal(t, "calico", engine.EngineName())
	})

	t.Run("Generate Basic Deny Policy", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
				UID:       types.UID("test-uid"),
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CalicoNetworkPolicy)
		assert.Equal(t, "test-policy-generated", policy.Name)
		assert.Equal(t, "test-namespace", policy.Namespace)
		assert.Equal(t, CalicoAPIVersion, policy.APIVersion)
		assert.Equal(t, CalicoKind, policy.Kind)
		assert.Equal(t, "all()", policy.Spec.Selector)
		assert.Contains(t, policy.Spec.Types, "Ingress")
		assert.Contains(t, policy.Spec.Types, "Egress")
		// Deny all: no ingress rules, only DNS egress
		assert.Empty(t, policy.Spec.Ingress)
		require.Len(t, policy.Spec.Egress, 1) // DNS only
		assert.Equal(t, CalicoActionAllow, policy.Spec.Egress[0].Action)
		assert.Equal(t, "UDP", policy.Spec.Egress[0].Protocol)
	})

	t.Run("Generate Deny Type with Allowed Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
				Policy: securityv1.PolicyConfig{
					Type:              "deny",
					AllowedNamespaces: []string{"allowed-ns1", "allowed-ns2"},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CalicoNetworkPolicy)
		assert.Equal(t, "test-namespace", policy.Namespace)
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Equal(t, CalicoActionAllow, policy.Spec.Ingress[0].Action)
		assert.Contains(t, policy.Spec.Ingress[0].Source.NamespaceSelector, "allowed-ns1")
		assert.Contains(t, policy.Spec.Ingress[0].Source.NamespaceSelector, "allowed-ns2")
		// 1 namespace egress + 1 DNS egress
		require.Len(t, policy.Spec.Egress, 2)
	})

	t.Run("Generate Allow Type with Denied Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
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
			policy := obj.(*CalicoNetworkPolicy)
			assert.Equal(t, spec.Spec.Policy.DeniedNamespaces[i], policy.Namespace)
			require.NotEmpty(t, policy.Spec.Ingress)
			assert.Equal(t, CalicoActionDeny, policy.Spec.Ingress[0].Action)
			require.NotEmpty(t, policy.Spec.Egress)
		}
	})

	t.Run("Allow Type with No Denied Namespaces", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
				Policy: securityv1.PolicyConfig{
					Type: "allow",
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		assert.Empty(t, objects)
	})

	t.Run("Generate Policy with Global Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
				GlobalRules: []securityv1.GlobalRule{
					{Direction: "ingress", Protocol: "TCP", Port: 80},
					{Direction: "egress", Protocol: "TCP", Port: 443},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CalicoNetworkPolicy)
		// 1 global ingress rule
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Equal(t, CalicoActionAllow, policy.Spec.Ingress[0].Action)
		assert.Equal(t, "TCP", policy.Spec.Ingress[0].Protocol)

		// 1 DNS egress + 1 global egress
		require.Len(t, policy.Spec.Egress, 2)
	})

	t.Run("Generate Policy with CIDR Rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
				CIDRRules: []securityv1.CIDRRule{
					{CIDR: "10.0.0.0/8", Direction: "egress"},
					{CIDR: "192.168.1.0/24", Except: []string{"192.168.1.100/32"}, Direction: "ingress"},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CalicoNetworkPolicy)
		// 1 DNS egress + 1 CIDR egress
		require.Len(t, policy.Spec.Egress, 2)
		assert.Contains(t, policy.Spec.Egress[1].Destination.Nets, "10.0.0.0/8")

		// 1 CIDR ingress
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Contains(t, policy.Spec.Ingress[0].Source.Nets, "192.168.1.0/24")
		assert.Contains(t, policy.Spec.Ingress[0].Source.NotNets, "192.168.1.100/32")
	})

	t.Run("Generate Policy with Pod Selector", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
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

		policy := objects[0].(*CalicoNetworkPolicy)
		assert.Contains(t, policy.Spec.Selector, "app == 'web'")
		assert.Contains(t, policy.Spec.Selector, "tier == 'frontend'")
	})

	t.Run("Generate Policy with Named Port", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				PolicyEngine: "calico",
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
				GlobalRules: []securityv1.GlobalRule{
					{Direction: "ingress", Protocol: "TCP", NamedPort: "http"},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)

		policy := objects[0].(*CalicoNetworkPolicy)
		require.Len(t, policy.Spec.Ingress, 1)
		assert.Equal(t, "http", policy.Spec.Ingress[0].Destination.Ports[0])
	})
}

func TestCalicoNetworkPolicyDeepCopy(t *testing.T) {
	order := float64(100)
	original := &CalicoNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: CalicoAPIVersion,
			Kind:       CalicoKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: &CalicoNetworkPolicySpec{
			Order:    &order,
			Selector: "all()",
			Types:    []string{"Ingress", "Egress"},
			Ingress: []CalicoRule{{
				Action: CalicoActionAllow,
				Source: &CalicoEntityRule{Nets: []string{"10.0.0.0/8"}},
			}},
			Egress: []CalicoRule{{
				Action:      CalicoActionAllow,
				Destination: &CalicoEntityRule{Nets: []string{"0.0.0.0/0"}},
			}},
		},
	}

	copied := original.DeepCopyObject().(*CalicoNetworkPolicy)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, *original.Spec.Order, *copied.Spec.Order)

	// Verify deep copy independence
	*copied.Spec.Order = 200
	assert.Equal(t, float64(100), *original.Spec.Order)

	copied.Spec.Ingress[0].Action = CalicoActionDeny
	assert.Equal(t, CalicoActionAllow, original.Spec.Ingress[0].Action)
}

func TestCalicoDeepCopyNil(t *testing.T) {
	var p *CalicoNetworkPolicy
	assert.Nil(t, p.DeepCopyObject())

	var spec *CalicoNetworkPolicySpec
	assert.Nil(t, spec.DeepCopy())

	var rule *CalicoRule
	assert.Nil(t, rule.DeepCopy())

	var entity *CalicoEntityRule
	assert.Nil(t, entity.DeepCopy())
}

func TestBuildCalicoSelector(t *testing.T) {
	t.Run("single label", func(t *testing.T) {
		result := buildCalicoSelector(map[string]string{"app": "web"})
		assert.Equal(t, "app == 'web'", result)
	})
}

func TestBuildCalicoNamespaceSelector(t *testing.T) {
	t.Run("single namespace", func(t *testing.T) {
		result := buildCalicoNamespaceSelector([]string{"ns1"})
		assert.Equal(t, "projectcalico.org/name == 'ns1'", result)
	})

	t.Run("multiple namespaces", func(t *testing.T) {
		result := buildCalicoNamespaceSelector([]string{"ns1", "ns2"})
		assert.Contains(t, result, "projectcalico.org/name in {")
		assert.Contains(t, result, "'ns1'")
		assert.Contains(t, result, "'ns2'")
	})
}
