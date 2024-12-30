package policy

import (
	"testing"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRules(t *testing.T) {
	t.Run("Generate Namespace Rules", func(t *testing.T) {
		namespaces := []string{"ns1", "ns2"}
		rules := GenerateNamespaceRules(namespaces)

		assert.Len(t, rules.Ingress, 1)
		assert.Len(t, rules.Egress, 1)
		assert.Len(t, rules.Ingress[0].From, 2)
		assert.Len(t, rules.Egress[0].To, 2)

		// Verify namespace selectors
		assert.Equal(t, "ns1",
			rules.Ingress[0].From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
		assert.Equal(t, "ns2",
			rules.Ingress[0].From[1].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
	})

	t.Run("Generate Denied Namespace Rules", func(t *testing.T) {
		namespaces := []string{"ns1", "ns2"}
		rules := GenerateDeniedNamespaceRules(namespaces)

		assert.Len(t, rules.Ingress, 1)
		assert.Len(t, rules.Egress, 1)

		// Verify NotIn operator and values
		ingressNS := rules.Ingress[0].From[0].NamespaceSelector.MatchExpressions[0]
		assert.Equal(t, "kubernetes.io/metadata.name", ingressNS.Key)
		assert.Equal(t, metav1.LabelSelectorOpNotIn, ingressNS.Operator)
		assert.ElementsMatch(t, namespaces, ingressNS.Values)

		// Verify egress rules
		egressNS := rules.Egress[0].To[0].NamespaceSelector.MatchExpressions[0]
		assert.Equal(t, "kubernetes.io/metadata.name", egressNS.Key)
		assert.Equal(t, metav1.LabelSelectorOpNotIn, egressNS.Operator)
		assert.ElementsMatch(t, namespaces, egressNS.Values)
	})

	t.Run("Generate Global Rules", func(t *testing.T) {
		globalRules := []securityv1.GlobalRule{
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
		}

		ingressRules, egressRules := GenerateGlobalRules(globalRules)

		// Verify ingress rules
		assert.Len(t, ingressRules, 1)
		assert.Equal(t, int32(80), ingressRules[0].Ports[0].Port.IntVal)
		assert.Equal(t, "0.0.0.0/0", ingressRules[0].From[0].IPBlock.CIDR)

		// Verify egress rules
		assert.Len(t, egressRules, 1)
		assert.Equal(t, int32(443), egressRules[0].Ports[0].Port.IntVal)
		assert.Equal(t, "0.0.0.0/0", egressRules[0].To[0].IPBlock.CIDR)
	})
}
