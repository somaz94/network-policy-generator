package policy

import (
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// Generator handles NetworkPolicy generation (kept for backward compatibility)
type Generator struct{}

// NewGenerator creates a new NetworkPolicy generator
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateNetworkPolicies creates NetworkPolicies for target namespaces
func (g *Generator) GenerateNetworkPolicies(generator *securityv1.NetworkPolicyGenerator) ([]*networkingv1.NetworkPolicy, error) {
	engine := &KubernetesEngine{}
	return engine.generateK8sPolicies(generator)
}

// KubernetesEngine generates standard Kubernetes NetworkPolicy resources
type KubernetesEngine struct{}

// NewKubernetesEngine creates a new Kubernetes policy engine
func NewKubernetesEngine() *KubernetesEngine {
	return &KubernetesEngine{}
}

// EngineName returns "kubernetes"
func (e *KubernetesEngine) EngineName() string {
	return EngineKubernetes
}

// GeneratePolicies implements PolicyEngine for standard Kubernetes NetworkPolicy
func (e *KubernetesEngine) GeneratePolicies(generator *securityv1.NetworkPolicyGenerator) ([]runtime.Object, error) {
	policies, err := e.generateK8sPolicies(generator)
	if err != nil {
		return nil, err
	}

	objects := make([]runtime.Object, len(policies))
	for i, p := range policies {
		objects[i] = p
	}
	return objects, nil
}

// generateK8sPolicies contains the core Kubernetes NetworkPolicy generation logic
func (e *KubernetesEngine) generateK8sPolicies(generator *securityv1.NetworkPolicyGenerator) ([]*networkingv1.NetworkPolicy, error) {
	basePolicy := newBaseNetworkPolicy(generator)

	var policies []*networkingv1.NetworkPolicy
	if generator.Spec.Policy.Type == PolicyTypeAllow {
		policies = e.generateAllowPolicies(basePolicy, generator)
	} else {
		policies = e.generateDenyPolicies(basePolicy, generator)
	}

	// Add DNS egress rule to all policies
	dnsRule := dnsEgressRule()
	for _, p := range policies {
		p.Spec.Egress = append(p.Spec.Egress, dnsRule)
	}

	// Apply global rules
	e.applyGlobalRules(policies, generator.Spec.GlobalRules)

	return policies, nil
}

// newBaseNetworkPolicy creates a base NetworkPolicy with common settings
func newBaseNetworkPolicy(generator *securityv1.NetworkPolicyGenerator) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyName(generator.Name),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: generator.APIVersion,
					Kind:       generator.Kind,
					Name:       generator.Name,
					UID:        generator.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// generateAllowPolicies creates policies that deny traffic from specified namespaces
func (e *KubernetesEngine) generateAllowPolicies(basePolicy *networkingv1.NetworkPolicy, generator *securityv1.NetworkPolicyGenerator) []*networkingv1.NetworkPolicy {
	var policies []*networkingv1.NetworkPolicy

	if len(generator.Spec.Policy.DeniedNamespaces) == 0 {
		return policies
	}

	for _, ns := range generator.Spec.Policy.DeniedNamespaces {
		policy := basePolicy.DeepCopy()
		policy.Namespace = ns

		rules := GenerateDeniedNamespaceRules(generator.Spec.Policy.DeniedNamespaces)
		policy.Spec.Ingress = rules.Ingress
		policy.Spec.Egress = rules.Egress

		policies = append(policies, policy)
	}

	return policies
}

// generateDenyPolicies creates policies that allow traffic only from specified namespaces
func (e *KubernetesEngine) generateDenyPolicies(basePolicy *networkingv1.NetworkPolicy, generator *securityv1.NetworkPolicyGenerator) []*networkingv1.NetworkPolicy {
	policy := basePolicy.DeepCopy()
	policy.Namespace = generator.Namespace

	if len(generator.Spec.Policy.AllowedNamespaces) > 0 {
		rules := GenerateNamespaceRules(generator.Spec.Policy.AllowedNamespaces)
		policy.Spec.Ingress = rules.Ingress
		policy.Spec.Egress = rules.Egress
	} else {
		policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
		policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{}
	}

	return []*networkingv1.NetworkPolicy{policy}
}

// applyGlobalRules adds global rules to all policies
func (e *KubernetesEngine) applyGlobalRules(policies []*networkingv1.NetworkPolicy, globalRules []securityv1.GlobalRule) {
	if globalRules == nil {
		return
	}

	for _, p := range policies {
		for _, rule := range globalRules {
			if rule.Direction == DirectionIngress {
				p.Spec.Ingress = append(p.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{
					Ports: []networkingv1.NetworkPolicyPort{{
						Protocol: (*v1.Protocol)(&rule.Protocol),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					}},
					From: []networkingv1.NetworkPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{CIDR: CIDRAllTraffic},
					}},
				})
			} else if rule.Direction == DirectionEgress {
				p.Spec.Egress = append(p.Spec.Egress, networkingv1.NetworkPolicyEgressRule{
					Ports: []networkingv1.NetworkPolicyPort{{
						Protocol: (*v1.Protocol)(&rule.Protocol),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					}},
					To: []networkingv1.NetworkPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{CIDR: CIDRAllTraffic},
					}},
				})
			}
		}
	}
}

// Ensure KubernetesEngine implements PolicyEngine (compile-time check)
var _ PolicyEngine = (*KubernetesEngine)(nil)
