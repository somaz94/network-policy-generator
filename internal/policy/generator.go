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

// GenerateNetworkPolicies creates NetworkPolicies for target namespaces
func (g *Generator) GenerateNetworkPolicies(generator *securityv1.NetworkPolicyGenerator) ([]*networkingv1.NetworkPolicy, error) {
	var policies []*networkingv1.NetworkPolicy

	// 기본 NetworkPolicy 객체 생성
	basePolicy := &networkingv1.NetworkPolicy{
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
		},
	}

	if generator.Spec.DefaultPolicy.Type == securityv1.PolicyAllow {
		if len(generator.Spec.DeniedNamespaces) > 0 {
			// Create policies for each denied namespace
			for _, ns := range generator.Spec.DeniedNamespaces {
				policy := basePolicy.DeepCopy()
				policy.Namespace = ns

				// Set up base rules with namespace restrictions
				policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   generator.Spec.DeniedNamespaces,
							}},
						},
					}},
				}}
				policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   generator.Spec.DeniedNamespaces,
							}},
						},
					}},
				}}

				// Add global rules
				if generator.Spec.GlobalAllowRules != nil && generator.Spec.GlobalAllowRules.Enabled {
					// Add traffic rules
					for _, rule := range generator.Spec.GlobalAllowRules.Traffic.Ingress {
						policy.Spec.Ingress = append(policy.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{
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
					}
					for _, rule := range generator.Spec.GlobalAllowRules.Traffic.Egress {
						policy.Spec.Egress = append(policy.Spec.Egress, networkingv1.NetworkPolicyEgressRule{
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

				if generator.Spec.GlobalDenyRules != nil && generator.Spec.GlobalDenyRules.Enabled {
					// Add deny traffic rules
					for _, rule := range generator.Spec.GlobalDenyRules.Traffic.Ingress {
						policy.Spec.Ingress = append(policy.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{
							Ports: []networkingv1.NetworkPolicyPort{{
								Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
								Port:     ptr.To(intstr.FromInt32(rule.Port)),
							}},
						})
					}
					for _, rule := range generator.Spec.GlobalDenyRules.Traffic.Egress {
						policy.Spec.Egress = append(policy.Spec.Egress, networkingv1.NetworkPolicyEgressRule{
							Ports: []networkingv1.NetworkPolicyPort{{
								Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
								Port:     ptr.To(intstr.FromInt32(rule.Port)),
							}},
						})
					}
				}

				policies = append(policies, policy)
			}
		}
	} else {
		// Default Deny policy
		policy := basePolicy.DeepCopy()

		// Add allowed namespaces if specified
		if len(generator.Spec.AllowedNamespaces) > 0 {
			var ingressPeers []networkingv1.NetworkPolicyPeer
			var egressPeers []networkingv1.NetworkPolicyPeer

			for _, ns := range generator.Spec.AllowedNamespaces {
				peer := networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": ns,
						},
					},
				}
				ingressPeers = append(ingressPeers, peer)
				egressPeers = append(egressPeers, peer)
			}

			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{From: ingressPeers}}
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: egressPeers}}
		}

		// Add global rules with traffic structure
		if generator.Spec.GlobalAllowRules != nil && generator.Spec.GlobalAllowRules.Enabled {
			if len(policy.Spec.Ingress) == 0 {
				policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
			}
			if len(policy.Spec.Egress) == 0 {
				policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
			}

			// Add traffic rules
			for _, rule := range generator.Spec.GlobalAllowRules.Traffic.Ingress {
				policy.Spec.Ingress[0].Ports = append(policy.Spec.Ingress[0].Ports,
					networkingv1.NetworkPolicyPort{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				)
			}
			for _, rule := range generator.Spec.GlobalAllowRules.Traffic.Egress {
				policy.Spec.Egress[0].Ports = append(policy.Spec.Egress[0].Ports,
					networkingv1.NetworkPolicyPort{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				)
			}
		}

		if generator.Spec.GlobalDenyRules != nil && generator.Spec.GlobalDenyRules.Enabled {
			if len(policy.Spec.Ingress) == 0 {
				policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
			}
			if len(policy.Spec.Egress) == 0 {
				policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
			}

			// Add deny traffic rules
			for _, rule := range generator.Spec.GlobalDenyRules.Traffic.Ingress {
				policy.Spec.Ingress[0].Ports = append(policy.Spec.Ingress[0].Ports,
					networkingv1.NetworkPolicyPort{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				)
			}
			for _, rule := range generator.Spec.GlobalDenyRules.Traffic.Egress {
				policy.Spec.Egress[0].Ports = append(policy.Spec.Egress[0].Ports,
					networkingv1.NetworkPolicyPort{
						Protocol: (*v1.Protocol)(ptr.To(rule.Protocol)),
						Port:     ptr.To(intstr.FromInt32(rule.Port)),
					},
				)
			}
		}

		policies = append(policies, policy)
	}

	return policies, nil
}
