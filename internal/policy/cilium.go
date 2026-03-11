package policy

import (
	"fmt"
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
	return "cilium"
}

// GeneratePolicies generates CiliumNetworkPolicy objects
func (e *CiliumEngine) GeneratePolicies(generator *securityv1.NetworkPolicyGenerator) ([]runtime.Object, error) {
	var policies []runtime.Object

	basePolicy := &CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
		},
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
		Spec: &CiliumNetworkPolicySpec{
			EndpointSelector: &CiliumEndpointSelector{},
		},
	}

	if generator.Spec.Policy.Type == "allow" {
		// Allow type: create policies in denied namespaces
		if len(generator.Spec.Policy.DeniedNamespaces) > 0 {
			for _, ns := range generator.Spec.Policy.DeniedNamespaces {
				policy := basePolicy.DeepCopyObject().(*CiliumNetworkPolicy)
				policy.Namespace = ns

				// Deny ingress from denied namespaces
				policy.Spec.IngressDeny = []CiliumIngressRule{{
					FromEndpoints: e.buildDeniedNamespaceSelectors(generator.Spec.Policy.DeniedNamespaces),
				}}
				// Deny egress to denied namespaces
				policy.Spec.EgressDeny = []CiliumEgressRule{{
					ToEndpoints: e.buildDeniedNamespaceSelectors(generator.Spec.Policy.DeniedNamespaces),
				}}

				// Allow DNS egress (kube-dns)
				policy.Spec.Egress = append(policy.Spec.Egress, e.dnsEgressRule())

				policies = append(policies, policy)
			}
		}
	} else {
		// Deny type: create policy in current namespace
		policy := basePolicy.DeepCopyObject().(*CiliumNetworkPolicy)
		policy.Namespace = generator.Namespace

		if len(generator.Spec.Policy.AllowedNamespaces) > 0 {
			// Allow only specific namespaces
			ingressEndpoints := e.buildAllowedNamespaceSelectors(generator.Spec.Policy.AllowedNamespaces)
			egressEndpoints := e.buildAllowedNamespaceSelectors(generator.Spec.Policy.AllowedNamespaces)

			policy.Spec.Ingress = []CiliumIngressRule{{
				FromEndpoints: ingressEndpoints,
			}}
			policy.Spec.Egress = []CiliumEgressRule{{
				ToEndpoints: egressEndpoints,
			}}
		}
		// If no AllowedNamespaces, empty Ingress/Egress = deny all

		// Add DNS egress
		policy.Spec.Egress = append(policy.Spec.Egress, e.dnsEgressRule())

		policies = append(policies, policy)
	}

	// Apply global rules
	if generator.Spec.GlobalRules != nil {
		for _, policy := range policies {
			ciliumPolicy := policy.(*CiliumNetworkPolicy)
			for _, rule := range generator.Spec.GlobalRules {
				portRule := CiliumPortRule{
					Ports: []CiliumPort{{
						Port:     strconv.Itoa(int(rule.Port)),
						Protocol: rule.Protocol,
					}},
				}
				if rule.Direction == "ingress" {
					ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, CiliumIngressRule{
						FromEntities: []string{"world"},
						ToPorts:      []CiliumPortRule{portRule},
					})
				} else if rule.Direction == "egress" {
					ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, CiliumEgressRule{
						ToEntities: []string{"world"},
						ToPorts:    []CiliumPortRule{portRule},
					})
				}
			}
		}
	}

	return policies, nil
}

// buildAllowedNamespaceSelectors creates endpoint selectors for allowed namespaces
func (e *CiliumEngine) buildAllowedNamespaceSelectors(namespaces []string) []CiliumEndpointSelector {
	selectors := make([]CiliumEndpointSelector, len(namespaces))
	for i, ns := range namespaces {
		selectors[i] = CiliumEndpointSelector{
			MatchLabels: map[string]string{
				"k8s:io.kubernetes.pod.namespace": ns,
			},
		}
	}
	return selectors
}

// buildDeniedNamespaceSelectors creates endpoint selectors for denied namespaces
func (e *CiliumEngine) buildDeniedNamespaceSelectors(namespaces []string) []CiliumEndpointSelector {
	selectors := make([]CiliumEndpointSelector, len(namespaces))
	for i, ns := range namespaces {
		selectors[i] = CiliumEndpointSelector{
			MatchLabels: map[string]string{
				"k8s:io.kubernetes.pod.namespace": ns,
			},
		}
	}
	return selectors
}

// dnsEgressRule creates a Cilium egress rule allowing DNS resolution
func (e *CiliumEngine) dnsEgressRule() CiliumEgressRule {
	return CiliumEgressRule{
		ToEndpoints: []CiliumEndpointSelector{{
			MatchLabels: map[string]string{
				"k8s:io.kubernetes.pod.namespace": "kube-system",
				"k8s:k8s-app":                     "kube-dns",
			},
		}},
		ToPorts: []CiliumPortRule{{
			Ports: []CiliumPort{
				{Port: "53", Protocol: "UDP"},
				{Port: "53", Protocol: "TCP"},
			},
		}},
	}
}
