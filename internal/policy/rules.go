package policy

import (
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// NamespaceRules contains both ingress and egress rules
type NamespaceRules struct {
	Ingress []networkingv1.NetworkPolicyIngressRule
	Egress  []networkingv1.NetworkPolicyEgressRule
}

// GenerateNamespaceRules generates rules for allowed namespaces
func GenerateNamespaceRules(namespaces []string) NamespaceRules {
	var rules NamespaceRules

	// Create a single rule with multiple namespace selectors
	ingressRule := networkingv1.NetworkPolicyIngressRule{
		From: make([]networkingv1.NetworkPolicyPeer, len(namespaces)),
	}
	egressRule := networkingv1.NetworkPolicyEgressRule{
		To: make([]networkingv1.NetworkPolicyPeer, len(namespaces)),
	}

	for i, ns := range namespaces {
		ingressRule.From[i] = networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": ns,
				},
			},
		}
		egressRule.To[i] = networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": ns,
				},
			},
		}
	}

	rules.Ingress = []networkingv1.NetworkPolicyIngressRule{ingressRule}
	rules.Egress = []networkingv1.NetworkPolicyEgressRule{egressRule}
	return rules
}

// GenerateDeniedNamespaceRules generates rules that exclude denied namespaces
func GenerateDeniedNamespaceRules(namespaces []string) NamespaceRules {
	var rules NamespaceRules

	if len(namespaces) > 0 {
		ingressRule := networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   namespaces,
							},
						},
					},
				},
			},
		}
		egressRule := networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   namespaces,
							},
						},
					},
				},
			},
		}
		rules.Ingress = []networkingv1.NetworkPolicyIngressRule{ingressRule}
		rules.Egress = []networkingv1.NetworkPolicyEgressRule{egressRule}
	}

	return rules
}

// GenerateGlobalRules generates rules based on global configuration
func GenerateGlobalRules(rules []securityv1.GlobalRule) ([]networkingv1.NetworkPolicyIngressRule, []networkingv1.NetworkPolicyEgressRule) {
	var ingressRules []networkingv1.NetworkPolicyIngressRule
	var egressRules []networkingv1.NetworkPolicyEgressRule

	for _, rule := range rules {
		if rule.Direction == "ingress" {
			ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
					Port:     ptr.To(intstr.FromInt32(rule.Port)),
				}},
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{
						CIDR: "0.0.0.0/0",
					},
				}},
			})
		} else if rule.Direction == "egress" {
			egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
					Port:     ptr.To(intstr.FromInt32(rule.Port)),
				}},
				To: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{
						CIDR: "0.0.0.0/0",
					},
				}},
			})
		}
	}

	return ingressRules, egressRules
}
