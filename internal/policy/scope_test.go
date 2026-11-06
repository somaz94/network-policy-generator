package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func scopedGenerator(engine string, allowed []string, from string) *securityv1.NetworkPolicyGenerator {
	return &securityv1.NetworkPolicyGenerator{
		ObjectMeta: metav1.ObjectMeta{Name: nameTestPolicy, Namespace: nsTest},
		Spec: securityv1.NetworkPolicyGeneratorSpec{
			PolicyEngine: engine,
			Policy:       securityv1.PolicyConfig{Type: PolicyTypeDeny, AllowedNamespaces: allowed},
			GlobalRules: []securityv1.GlobalRule{
				{Type: PolicyTypeAllow, Port: 5432, Protocol: ProtocolTCP, Direction: DirectionIngress, From: from},
			},
		},
	}
}

func TestResolveScope(t *testing.T) {
	rule := securityv1.GlobalRule{}
	gen := scopedGenerator(EngineKubernetes, []string{labelApp}, "")

	assert.Equal(t, ruleScope{anywhere: true}, resolveScope(rule, gen, "db"), "empty from is anywhere")

	rule.From = FromAnywhere
	assert.Equal(t, ruleScope{anywhere: true}, resolveScope(rule, gen, "db"))

	rule.From = FromAllowedNamespaces
	assert.Equal(t, ruleScope{namespaces: []string{labelApp}}, resolveScope(rule, gen, "db"))

	gen.Spec.Policy.AllowedNamespaces = nil
	assert.Equal(t, ruleScope{namespaces: []string{"db"}}, resolveScope(rule, gen, "db"),
		"an empty allowed list narrows to the policy namespace, never widens to anywhere")

	rule.From = FromSameNamespace
	assert.Equal(t, ruleScope{namespaces: []string{"db"}}, resolveScope(rule, gen, "db"))
}

func TestKubernetesGlobalRuleScopes(t *testing.T) {
	policies, err := NewKubernetesEngine().generateK8sPolicies(scopedGenerator(EngineKubernetes, []string{labelApp}, FromAllowedNamespaces))
	require.NoError(t, err)
	global := policies[0].Spec.Ingress[len(policies[0].Spec.Ingress)-1]
	require.Len(t, global.From, 1)
	assert.Equal(t, labelApp, global.From[0].NamespaceSelector.MatchLabels[LabelK8sNamespace])
	assert.Nil(t, global.From[0].IPBlock)

	policies, err = NewKubernetesEngine().generateK8sPolicies(scopedGenerator(EngineKubernetes, nil, FromAnywhere))
	require.NoError(t, err)
	global = policies[0].Spec.Ingress[len(policies[0].Spec.Ingress)-1]
	assert.Empty(t, global.From, "anywhere lists no peers")
}

func TestCiliumGlobalRuleScopes(t *testing.T) {
	objects, err := NewCiliumEngine().GeneratePolicies(scopedGenerator(EngineCilium, []string{labelApp}, FromAllowedNamespaces))
	require.NoError(t, err)
	p := objects[0].(*CiliumNetworkPolicy)
	global := p.Spec.Ingress[len(p.Spec.Ingress)-1]
	assert.Empty(t, global.FromEntities)
	require.Len(t, global.FromEndpoints, 1)
	assert.Equal(t, labelApp, global.FromEndpoints[0].MatchLabels[LabelCiliumPodNS])
}

func TestCalicoGlobalRuleScopes(t *testing.T) {
	objects, err := NewCalicoEngine().GeneratePolicies(scopedGenerator(EngineCalico, []string{labelApp}, FromAllowedNamespaces))
	require.NoError(t, err)
	p := objects[0].(*CalicoNetworkPolicy)
	global := p.Spec.Ingress[len(p.Spec.Ingress)-1]
	require.NotNil(t, global.Source)
	assert.Equal(t, "projectcalico.org/name == '"+labelApp+"'", global.Source.NamespaceSelector)

	objects, err = NewCalicoEngine().GeneratePolicies(scopedGenerator(EngineCalico, nil, FromAnywhere))
	require.NoError(t, err)
	p = objects[0].(*CalicoNetworkPolicy)
	assert.Nil(t, p.Spec.Ingress[len(p.Spec.Ingress)-1].Source, "anywhere selects no source")
}

func TestDatabaseTemplateScopesIngressToAllowedNamespaces(t *testing.T) {
	spec := &securityv1.NetworkPolicyGeneratorSpec{}
	GetTemplate(TemplateDatabase).Apply(spec)
	for _, r := range spec.GlobalRules {
		if r.Direction == DirectionIngress {
			assert.Equal(t, FromAllowedNamespaces, r.From, "port %d", r.Port)
		}
	}
}

func denyGenerator(engine string) *securityv1.NetworkPolicyGenerator {
	gen := scopedGenerator(engine, []string{labelApp}, FromAnywhere)
	gen.Spec.GlobalRules = append(gen.Spec.GlobalRules, securityv1.GlobalRule{
		Type: PolicyTypeDeny, Port: 25, Protocol: ProtocolTCP, Direction: DirectionEgress,
	})
	return gen
}

func TestKubernetesSkipsDenyRules(t *testing.T) {
	policies, err := NewKubernetesEngine().generateK8sPolicies(denyGenerator(EngineKubernetes))
	require.NoError(t, err)
	for _, rule := range policies[0].Spec.Egress {
		for _, p := range rule.Ports {
			assert.NotEqual(t, int32(25), p.Port.IntVal, "a deny rule must never become an allow")
		}
	}
}

func TestCiliumDenyRules(t *testing.T) {
	objects, err := NewCiliumEngine().GeneratePolicies(denyGenerator(EngineCilium))
	require.NoError(t, err)
	p := objects[0].(*CiliumNetworkPolicy)
	require.Len(t, p.Spec.EgressDeny, 1)
	assert.Equal(t, "25", p.Spec.EgressDeny[0].ToPorts[0].Ports[0].Port)
	for _, rule := range p.Spec.Egress {
		for _, pr := range rule.ToPorts {
			assert.NotEqual(t, "25", pr.Ports[0].Port)
		}
	}
}

func TestCalicoDenyRulesComeFirst(t *testing.T) {
	objects, err := NewCalicoEngine().GeneratePolicies(denyGenerator(EngineCalico))
	require.NoError(t, err)
	p := objects[0].(*CalicoNetworkPolicy)
	require.NotEmpty(t, p.Spec.Egress)
	assert.Equal(t, CalicoActionDeny, p.Spec.Egress[0].Action, "Calico stops at the first match, so deny goes first")
	assert.Equal(t, []interface{}{"25"}, p.Spec.Egress[0].Destination.Ports)
	for _, rule := range p.Spec.Egress[1:] {
		assert.Equal(t, CalicoActionAllow, rule.Action)
	}
}
