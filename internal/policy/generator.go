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
			Name: fmt.Sprintf("%s-generated", generator.Name),
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

	// Policy Type에 따른 정책 생성
	if generator.Spec.Policy.Type == "allow" {
		// Allow 타입: DeniedNamespaces에 정책 생성
		if len(generator.Spec.Policy.DeniedNamespaces) > 0 {
			for _, ns := range generator.Spec.Policy.DeniedNamespaces {
				policy := basePolicy.DeepCopy()
				policy.Namespace = ns

				// 기본 규칙 설정
				policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   generator.Spec.Policy.DeniedNamespaces,
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
								Values:   generator.Spec.Policy.DeniedNamespaces,
							}},
						},
					}},
				}}

				policies = append(policies, policy)
			}
		}
	} else {
		// Deny 타입: 현재 네임스페이스에 정책 생성
		policy := basePolicy.DeepCopy()
		policy.Namespace = generator.Namespace

		if len(generator.Spec.Policy.AllowedNamespaces) > 0 {
			// AllowedNamespaces만 허용
			var ingressPeers []networkingv1.NetworkPolicyPeer
			var egressPeers []networkingv1.NetworkPolicyPeer

			for _, ns := range generator.Spec.Policy.AllowedNamespaces {
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
		} else {
			// 모든 트래픽 차단
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{}
		}

		policies = append(policies, policy)
	}

	// DNS egress 규칙 추가 (kube-dns/coredns 접근 허용)
	dnsEgressRule := dnsEgressRule()
	for _, policy := range policies {
		policy.Spec.Egress = append(policy.Spec.Egress, dnsEgressRule)
	}

	// Global Rules 적용
	if generator.Spec.GlobalRules != nil {
		for _, policy := range policies {
			// Add global ingress rules
			for _, rule := range generator.Spec.GlobalRules {
				if rule.Direction == "ingress" {
					policy.Spec.Ingress = append(policy.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{
						Ports: []networkingv1.NetworkPolicyPort{{
							Protocol: (*v1.Protocol)(&rule.Protocol),
							Port:     ptr.To(intstr.FromInt32(rule.Port)),
						}},
						From: []networkingv1.NetworkPolicyPeer{{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
							},
						}},
					})
				} else if rule.Direction == "egress" {
					policy.Spec.Egress = append(policy.Spec.Egress, networkingv1.NetworkPolicyEgressRule{
						Ports: []networkingv1.NetworkPolicyPort{{
							Protocol: (*v1.Protocol)(&rule.Protocol),
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
		}
	}

	return policies, nil
}
