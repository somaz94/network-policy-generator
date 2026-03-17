package policy

import (
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// CiliumEngine generates CiliumNetworkPolicy resources
type CiliumEngine struct{}

// NewCiliumEngine creates a new Cilium policy engine
func NewCiliumEngine() *CiliumEngine {
	return &CiliumEngine{}
}

// EngineName returns "cilium"
func (e *CiliumEngine) EngineName() string {
	return EngineCilium
}

// GeneratePolicies generates CiliumNetworkPolicy objects
func (e *CiliumEngine) GeneratePolicies(generator *securityv1.NetworkPolicyGenerator) ([]runtime.Object, error) {
	var policies []runtime.Object

	endpointSelector := &CiliumEndpointSelector{}
	if len(generator.Spec.Policy.PodSelector) > 0 {
		endpointSelector.MatchLabels = generator.Spec.Policy.PodSelector
	}

	basePolicy := &CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: CiliumAPIVersion,
			Kind:       CiliumKind,
		},
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
		Spec: &CiliumNetworkPolicySpec{
			EndpointSelector: endpointSelector,
		},
	}

	if generator.Spec.Policy.Type == PolicyTypeAllow {
		policies = e.generateAllowPolicies(basePolicy, generator)
	} else {
		policies = e.generateDenyPolicies(basePolicy, generator)
	}

	e.applyGlobalRules(policies, generator.Spec.GlobalRules)
	e.applyCIDRRules(policies, generator.Spec.CIDRRules)

	return policies, nil
}

// generateAllowPolicies creates policies for allow type (deny in specified namespaces)
func (e *CiliumEngine) generateAllowPolicies(basePolicy *CiliumNetworkPolicy, generator *securityv1.NetworkPolicyGenerator) []runtime.Object {
	var policies []runtime.Object

	if len(generator.Spec.Policy.DeniedNamespaces) == 0 {
		return policies
	}

	for _, ns := range generator.Spec.Policy.DeniedNamespaces {
		policy := basePolicy.DeepCopyObject().(*CiliumNetworkPolicy)
		policy.Namespace = ns

		selectors := buildCiliumNamespaceSelectors(generator.Spec.Policy.DeniedNamespaces)
		policy.Spec.IngressDeny = []CiliumIngressRule{{FromEndpoints: selectors}}
		policy.Spec.EgressDeny = []CiliumEgressRule{{ToEndpoints: selectors}}
		policy.Spec.Egress = append(policy.Spec.Egress, dnsEgressRuleCilium())

		policies = append(policies, policy)
	}

	return policies
}

// generateDenyPolicies creates policies for deny type (allow only specified namespaces)
func (e *CiliumEngine) generateDenyPolicies(basePolicy *CiliumNetworkPolicy, generator *securityv1.NetworkPolicyGenerator) []runtime.Object {
	policy := basePolicy.DeepCopyObject().(*CiliumNetworkPolicy)
	policy.Namespace = generator.Namespace

	if len(generator.Spec.Policy.AllowedNamespaces) > 0 {
		selectors := buildCiliumNamespaceSelectors(generator.Spec.Policy.AllowedNamespaces)
		policy.Spec.Ingress = []CiliumIngressRule{{FromEndpoints: selectors}}
		policy.Spec.Egress = []CiliumEgressRule{{ToEndpoints: selectors}}
	}

	policy.Spec.Egress = append(policy.Spec.Egress, dnsEgressRuleCilium())

	return []runtime.Object{policy}
}

// ciliumGlobalRulePort returns the port string for a GlobalRule (named port or numeric)
func ciliumGlobalRulePort(rule securityv1.GlobalRule) string {
	if rule.NamedPort != "" {
		return rule.NamedPort
	}
	return strconv.Itoa(int(rule.Port))
}

// applyGlobalRules adds global rules to all policies
func (e *CiliumEngine) applyGlobalRules(policies []runtime.Object, globalRules []securityv1.GlobalRule) {
	if globalRules == nil {
		return
	}

	for _, obj := range policies {
		ciliumPolicy := obj.(*CiliumNetworkPolicy)
		for _, rule := range globalRules {
			portRule := CiliumPortRule{
				Ports: []CiliumPort{{
					Port:     ciliumGlobalRulePort(rule),
					Protocol: rule.Protocol,
				}},
			}
			switch rule.Direction {
			case DirectionIngress:
				ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, CiliumIngressRule{
					FromEntities: []string{EntityWorld},
					ToPorts:      []CiliumPortRule{portRule},
				})
			case DirectionEgress:
				ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, CiliumEgressRule{
					ToEntities: []string{EntityWorld},
					ToPorts:    []CiliumPortRule{portRule},
				})
			}
		}
	}
}

// applyCIDRRules adds CIDR-based rules to all Cilium policies
func (e *CiliumEngine) applyCIDRRules(policies []runtime.Object, cidrRules []securityv1.CIDRRule) {
	if cidrRules == nil {
		return
	}

	for _, obj := range policies {
		ciliumPolicy := obj.(*CiliumNetworkPolicy)
		for _, rule := range cidrRules {
			switch rule.Direction {
			case DirectionIngress:
				ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, CiliumIngressRule{
					FromCIDR: []string{rule.CIDR},
				})
			case DirectionEgress:
				ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, CiliumEgressRule{
					ToCIDR: []string{rule.CIDR},
				})
			}
		}
	}
}

// buildCiliumNamespaceSelectors creates endpoint selectors for namespaces
func buildCiliumNamespaceSelectors(namespaces []string) []CiliumEndpointSelector {
	selectors := make([]CiliumEndpointSelector, len(namespaces))
	for i, ns := range namespaces {
		selectors[i] = CiliumEndpointSelector{
			MatchLabels: map[string]string{
				LabelCiliumPodNS: ns,
			},
		}
	}
	return selectors
}

// dnsEgressRuleCilium creates a Cilium egress rule allowing DNS resolution
func dnsEgressRuleCilium() CiliumEgressRule {
	return CiliumEgressRule{
		ToEndpoints: []CiliumEndpointSelector{{
			MatchLabels: map[string]string{
				LabelCiliumPodNS:  LabelCiliumKubeSystem,
				LabelCiliumK8sApp: LabelCiliumKubeDNSApp,
			},
		}},
		ToPorts: []CiliumPortRule{{
			Ports: []CiliumPort{
				{Port: DNSPortStr, Protocol: "UDP"},
				{Port: DNSPortStr, Protocol: "TCP"},
			},
		}},
	}
}

// Ensure CiliumEngine implements PolicyEngine (compile-time check)
var _ PolicyEngine = (*CiliumEngine)(nil)
