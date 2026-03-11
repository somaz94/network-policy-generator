package policy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CiliumNetworkPolicy is a minimal representation of cilium.io/v2 CiliumNetworkPolicy
// We define this locally to avoid importing the full Cilium dependency
type CiliumNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired Cilium specific rule specification
	Spec *CiliumNetworkPolicySpec `json:"spec,omitempty"`
}

// CiliumNetworkPolicySpec defines the policy specification for Cilium
type CiliumNetworkPolicySpec struct {
	// EndpointSelector selects which endpoints this policy applies to
	EndpointSelector *CiliumEndpointSelector `json:"endpointSelector,omitempty"`

	// Ingress is a list of ingress rules
	// +optional
	Ingress []CiliumIngressRule `json:"ingress,omitempty"`

	// Egress is a list of egress rules
	// +optional
	Egress []CiliumEgressRule `json:"egress,omitempty"`

	// IngressDeny is a list of ingress deny rules
	// +optional
	IngressDeny []CiliumIngressRule `json:"ingressDeny,omitempty"`

	// EgressDeny is a list of egress deny rules
	// +optional
	EgressDeny []CiliumEgressRule `json:"egressDeny,omitempty"`
}

// CiliumEndpointSelector is a wrapper for label selectors
type CiliumEndpointSelector struct {
	// MatchLabels is a map of {key,value} pairs
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// CiliumIngressRule defines an ingress rule for Cilium
type CiliumIngressRule struct {
	// FromEndpoints is a list of endpoints identified by an EndpointSelector
	// +optional
	FromEndpoints []CiliumEndpointSelector `json:"fromEndpoints,omitempty"`

	// FromEntities is a list of special entities (e.g., "world", "cluster", "host")
	// +optional
	FromEntities []string `json:"fromEntities,omitempty"`

	// FromCIDR is a list of CIDRs allowed as ingress sources
	// +optional
	FromCIDR []string `json:"fromCIDR,omitempty"`

	// ToPorts is a list of destination L4 ports with protocol
	// +optional
	ToPorts []CiliumPortRule `json:"toPorts,omitempty"`
}

// CiliumEgressRule defines an egress rule for Cilium
type CiliumEgressRule struct {
	// ToEndpoints is a list of endpoints identified by an EndpointSelector
	// +optional
	ToEndpoints []CiliumEndpointSelector `json:"toEndpoints,omitempty"`

	// ToEntities is a list of special entities
	// +optional
	ToEntities []string `json:"toEntities,omitempty"`

	// ToCIDR is a list of CIDRs allowed as egress destinations
	// +optional
	ToCIDR []string `json:"toCIDR,omitempty"`

	// ToPorts is a list of destination L4 ports with protocol
	// +optional
	ToPorts []CiliumPortRule `json:"toPorts,omitempty"`
}

// CiliumPortRule defines L4 port/protocol rules
type CiliumPortRule struct {
	// Ports is a list of L4 port rules
	Ports []CiliumPort `json:"ports,omitempty"`
}

// CiliumPort represents a single L4 port/protocol pair
type CiliumPort struct {
	// Port is the L4 port number
	Port string `json:"port,omitempty"`

	// Protocol is the L4 protocol (TCP, UDP, ANY)
	Protocol string `json:"protocol,omitempty"`
}

// DeepCopyObject implements runtime.Object
func (in *CiliumNetworkPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(CiliumNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another CiliumNetworkPolicy
func (in *CiliumNetworkPolicy) DeepCopyInto(out *CiliumNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Spec != nil {
		out.Spec = in.Spec.DeepCopy()
	}
}

// DeepCopy creates a deep copy of CiliumNetworkPolicySpec
func (in *CiliumNetworkPolicySpec) DeepCopy() *CiliumNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(CiliumNetworkPolicySpec)
	if in.EndpointSelector != nil {
		out.EndpointSelector = in.EndpointSelector.DeepCopy()
	}
	if in.Ingress != nil {
		out.Ingress = make([]CiliumIngressRule, len(in.Ingress))
		copy(out.Ingress, in.Ingress)
	}
	if in.Egress != nil {
		out.Egress = make([]CiliumEgressRule, len(in.Egress))
		copy(out.Egress, in.Egress)
	}
	if in.IngressDeny != nil {
		out.IngressDeny = make([]CiliumIngressRule, len(in.IngressDeny))
		copy(out.IngressDeny, in.IngressDeny)
	}
	if in.EgressDeny != nil {
		out.EgressDeny = make([]CiliumEgressRule, len(in.EgressDeny))
		copy(out.EgressDeny, in.EgressDeny)
	}
	return out
}

// DeepCopy creates a deep copy of CiliumEndpointSelector
func (in *CiliumEndpointSelector) DeepCopy() *CiliumEndpointSelector {
	if in == nil {
		return nil
	}
	out := new(CiliumEndpointSelector)
	if in.MatchLabels != nil {
		out.MatchLabels = make(map[string]string, len(in.MatchLabels))
		for k, v := range in.MatchLabels {
			out.MatchLabels[k] = v
		}
	}
	return out
}
