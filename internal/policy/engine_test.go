package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestNewPolicyEngine(t *testing.T) {
	t.Run("Kubernetes engine", func(t *testing.T) {
		engine, err := NewPolicyEngine("kubernetes")
		require.NoError(t, err)
		assert.Equal(t, "kubernetes", engine.EngineName())
	})

	t.Run("Empty string defaults to Kubernetes", func(t *testing.T) {
		engine, err := NewPolicyEngine("")
		require.NoError(t, err)
		assert.Equal(t, "kubernetes", engine.EngineName())
	})

	t.Run("Cilium engine", func(t *testing.T) {
		engine, err := NewPolicyEngine("cilium")
		require.NoError(t, err)
		assert.Equal(t, "cilium", engine.EngineName())
	})

	t.Run("Calico engine", func(t *testing.T) {
		engine, err := NewPolicyEngine("calico")
		require.NoError(t, err)
		assert.Equal(t, "calico", engine.EngineName())
	})

	t.Run("Unsupported engine", func(t *testing.T) {
		engine, err := NewPolicyEngine("unknown")
		assert.Error(t, err)
		assert.Nil(t, engine)
		assert.Contains(t, err.Error(), "unsupported policy engine")
	})
}

func TestKubernetesEngineInterface(t *testing.T) {
	engine := NewKubernetesEngine()

	t.Run("EngineName", func(t *testing.T) {
		assert.Equal(t, "kubernetes", engine.EngineName())
	})

	t.Run("GeneratePolicies returns runtime.Object slice", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type: "deny",
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)
		assert.NotNil(t, objects[0])
	})
}

func TestCiliumEngineInterface(t *testing.T) {
	engine := NewCiliumEngine()

	t.Run("GeneratePolicies returns runtime.Object slice", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Policy: securityv1.PolicyConfig{
					Type:              "deny",
					AllowedNamespaces: []string{"ns1"},
				},
			},
		}

		objects, err := engine.GeneratePolicies(spec)
		require.NoError(t, err)
		require.Len(t, objects, 1)
		assert.NotNil(t, objects[0])
	})
}
