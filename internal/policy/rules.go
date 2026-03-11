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

	ingressRule := networkingv1.NetworkPolicyIngressRule{
		From: make([]networkingv1.NetworkPolicyPeer, len(namespaces)),
	}
	egressRule := networkingv1.NetworkPolicyEgressRule{
		To: make([]networkingv1.NetworkPolicyPeer, len(namespaces)),
	}

	for i, ns := range namespaces {
		peer := namespacePeer(ns)
		ingressRule.From[i] = peer
		egressRule.To[i] = peer
	}

	rules.Ingress = []networkingv1.NetworkPolicyIngressRule{ingressRule}
	rules.Egress = []networkingv1.NetworkPolicyEgressRule{egressRule}
	return rules
}

// GenerateDeniedNamespaceRules generates rules that exclude denied namespaces
func GenerateDeniedNamespaceRules(namespaces []string) NamespaceRules {
	var rules NamespaceRules

	if len(namespaces) == 0 {
		return rules
	}

	excludePeer := networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      LabelK8sNamespace,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   namespaces,
			}},
		},
	}

	rules.Ingress = []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{excludePeer},
	}}
	rules.Egress = []networkingv1.NetworkPolicyEgressRule{{
		To: []networkingv1.NetworkPolicyPeer{excludePeer},
	}}

	return rules
}

// namespacePeer creates a NetworkPolicyPeer that matches a specific namespace
func namespacePeer(namespace string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				LabelK8sNamespace: namespace,
			},
		},
	}
}

// dnsEgressRule creates an egress rule that allows DNS resolution (UDP/TCP port 53)
func dnsEgressRule() networkingv1.NetworkPolicyEgressRule {
	udp := v1.ProtocolUDP
	tcp := v1.ProtocolTCP
	dnsPort := intstr.FromInt32(DNSPort)

	return networkingv1.NetworkPolicyEgressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: &udp, Port: &dnsPort},
			{Protocol: &tcp, Port: &dnsPort},
		},
	}
}

// GenerateGlobalRules generates rules based on global configuration
func GenerateGlobalRules(rules []securityv1.GlobalRule) ([]networkingv1.NetworkPolicyIngressRule, []networkingv1.NetworkPolicyEgressRule) {
	var ingressRules []networkingv1.NetworkPolicyIngressRule
	var egressRules []networkingv1.NetworkPolicyEgressRule

	for _, rule := range rules {
		if rule.Direction == DirectionIngress {
			ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
					Port:     ptr.To(intstr.FromInt32(rule.Port)),
				}},
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: CIDRAllTraffic},
				}},
			})
		} else if rule.Direction == DirectionEgress {
			egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
					Port:     ptr.To(intstr.FromInt32(rule.Port)),
				}},
				To: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: CIDRAllTraffic},
				}},
			})
		}
	}

	return ingressRules, egressRules
}
