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

// GenerateIngressRules generates ingress rules based on observed traffic
func GenerateIngressRules(flows []securityv1.TrafficFlow) []networkingv1.NetworkPolicyIngressRule {
	rules := make([]networkingv1.NetworkPolicyIngressRule, 0)
	for _, flow := range flows {
		rule := networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": flow.SourceNamespace,
						},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: (*v1.Protocol)(ptr.To(flow.Protocol)),
					Port:     ptr.To(intstr.FromInt32(flow.Port)),
				},
			},
		}
		rules = append(rules, rule)
	}
	return rules
}

// GenerateEgressRules generates egress rules based on observed traffic
func GenerateEgressRules(flows []securityv1.TrafficFlow) []networkingv1.NetworkPolicyEgressRule {
	rules := make([]networkingv1.NetworkPolicyEgressRule, 0)
	for _, flow := range flows {
		rule := networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": flow.DestNamespace,
						},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: (*v1.Protocol)(ptr.To(flow.Protocol)),
					Port:     ptr.To(intstr.FromInt32(flow.Port)),
				},
			},
		}
		rules = append(rules, rule)
	}
	return rules
}
