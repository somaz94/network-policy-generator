package policy

import (
	"fmt"

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
	return "kubernetes"
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
	var policies []*networkingv1.NetworkPolicy

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

	if generator.Spec.Policy.Type == "allow" {
		if len(generator.Spec.Policy.DeniedNamespaces) > 0 {
			for _, ns := range generator.Spec.Policy.DeniedNamespaces {
				policy := basePolicy.DeepCopy()
				policy.Namespace = ns

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
		policy := basePolicy.DeepCopy()
		policy.Namespace = generator.Namespace

		if len(generator.Spec.Policy.AllowedNamespaces) > 0 {
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
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{}
		}

		policies = append(policies, policy)
	}

	// DNS egress rule
	dnsRule := dnsEgressRule()
	for _, policy := range policies {
		policy.Spec.Egress = append(policy.Spec.Egress, dnsRule)
	}

	// Global rules
	if generator.Spec.GlobalRules != nil {
		for _, policy := range policies {
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
