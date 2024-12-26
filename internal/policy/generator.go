package policy

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// Generator handles NetworkPolicy generation
type Generator struct{}

// NewGenerator creates a new NetworkPolicy generator
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateNetworkPolicy creates a NetworkPolicy based on the generator spec
func (g *Generator) GenerateNetworkPolicy(generator *securityv1.NetworkPolicyGenerator) (*networkingv1.NetworkPolicy, error) {
	// 기본 NetworkPolicy 객체 생성
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-generated", generator.Name),
			Namespace: generator.Namespace,
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
			// Initialize empty slices for rules
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  []networkingv1.NetworkPolicyEgressRule{},
		},
	}

	// Handle default policy type
	if generator.Spec.DefaultPolicy.Type == securityv1.PolicyAllow {
		if len(generator.Spec.DeniedNamespaces) > 0 {
			// Create namespace selector for denied namespaces
			namespaceSelector := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "kubernetes.io/metadata.name",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   generator.Spec.DeniedNamespaces,
					},
				},
			}

			// Set ingress rules with From field
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: namespaceSelector,
						},
					},
				},
			}

			// Set egress rules with To field
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: namespaceSelector,
						},
					},
				},
			}
		}
	} else {
		// Handle deny default policy
		if len(generator.Spec.AllowedNamespaces) > 0 {
			// Create ingress rules for allowed namespaces
			var ingressPeers []networkingv1.NetworkPolicyPeer
			for _, ns := range generator.Spec.AllowedNamespaces {
				ingressPeers = append(ingressPeers, networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": ns,
						},
					},
				})
			}
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
				{
					From: ingressPeers,
				},
			}

			// Create egress rules for allowed namespaces
			var egressPeers []networkingv1.NetworkPolicyPeer
			for _, ns := range generator.Spec.AllowedNamespaces {
				egressPeers = append(egressPeers, networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": ns,
						},
					},
				})
			}
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					To: egressPeers,
				},
			}
		}
	}

	// Add global allow rules
	if generator.Spec.GlobalAllowRules != nil && generator.Spec.GlobalAllowRules.Enabled {
		for _, rule := range generator.Spec.GlobalAllowRules.Ingress {
			ingressRule := networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				},
				From: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "0.0.0.0/0",
						},
					},
				},
			}
			policy.Spec.Ingress = append(policy.Spec.Ingress, ingressRule)
		}

		for _, rule := range generator.Spec.GlobalAllowRules.Egress {
			egressRule := networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				},
				To: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "0.0.0.0/0",
						},
					},
				},
			}
			policy.Spec.Egress = append(policy.Spec.Egress, egressRule)
		}
	}

	// Add global deny rules
	if generator.Spec.GlobalDenyRules != nil && generator.Spec.GlobalDenyRules.Enabled {
		for _, rule := range generator.Spec.GlobalDenyRules.Ingress {
			ingressRule := networkingv1.NetworkPolicyIngressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				},
			}
			policy.Spec.Ingress = append(policy.Spec.Ingress, ingressRule)
		}

		for _, rule := range generator.Spec.GlobalDenyRules.Egress {
			egressRule := networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				},
			}
			policy.Spec.Egress = append(policy.Spec.Egress, egressRule)
		}
	}

	return policy, nil
}
