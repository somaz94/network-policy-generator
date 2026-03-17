package policy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CalicoNetworkPolicy is a minimal representation of crd.projectcalico.org/v1 NetworkPolicy
// We define this locally to avoid importing the full Calico dependency
type CalicoNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec *CalicoNetworkPolicySpec `json:"spec,omitempty"`
}

// CalicoNetworkPolicySpec defines the Calico NetworkPolicy specification
type CalicoNetworkPolicySpec struct {
	// Order controls the order of precedence. Lower order is higher precedence.
	// +optional
	Order *float64 `json:"order,omitempty"`

	// Selector selects pods in this policy's namespace
	// +optional
	Selector string `json:"selector,omitempty"`

	// Ingress is a list of ingress rules
	// +optional
	Ingress []CalicoRule `json:"ingress,omitempty"`

	// Egress is a list of egress rules
	// +optional
	Egress []CalicoRule `json:"egress,omitempty"`

	// Types indicates whether this policy applies to ingress, egress, or both
	// +optional
	Types []string `json:"types,omitempty"`
}

// CalicoRule defines a single Calico network policy rule
type CalicoRule struct {
	// Action specifies the action to take: Allow, Deny, Log, Pass
	Action string `json:"action"`

	// Protocol is the protocol to match (TCP, UDP, ICMP, etc.)
	// +optional
	Protocol string `json:"protocol,omitempty"`

	// Source is the source endpoint match criteria
	// +optional
	Source *CalicoEntityRule `json:"source,omitempty"`

	// Destination is the destination endpoint match criteria
	// +optional
	Destination *CalicoEntityRule `json:"destination,omitempty"`
}

// CalicoEntityRule defines match criteria for an endpoint
type CalicoEntityRule struct {
	// Selector is a label selector for endpoints
	// +optional
	Selector string `json:"selector,omitempty"`

	// NamespaceSelector is a label selector for namespaces
	// +optional
	NamespaceSelector string `json:"namespaceSelector,omitempty"`

	// Nets is a list of CIDRs
	// +optional
	Nets []string `json:"nets,omitempty"`

	// NotNets is a list of CIDRs to exclude
	// +optional
	NotNets []string `json:"notNets,omitempty"`

	// Ports is a list of ports or port ranges
	// +optional
	Ports []interface{} `json:"ports,omitempty"`
}

// DeepCopyObject implements runtime.Object
func (in *CalicoNetworkPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(CalicoNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties into another CalicoNetworkPolicy
func (in *CalicoNetworkPolicy) DeepCopyInto(out *CalicoNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Spec != nil {
		out.Spec = in.Spec.DeepCopy()
	}
}

// DeepCopy creates a deep copy of CalicoNetworkPolicySpec
func (in *CalicoNetworkPolicySpec) DeepCopy() *CalicoNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(CalicoNetworkPolicySpec)
	if in.Order != nil {
		order := *in.Order
		out.Order = &order
	}
	out.Selector = in.Selector
	if in.Ingress != nil {
		out.Ingress = make([]CalicoRule, len(in.Ingress))
		for i, r := range in.Ingress {
			out.Ingress[i] = *r.DeepCopy()
		}
	}
	if in.Egress != nil {
		out.Egress = make([]CalicoRule, len(in.Egress))
		for i, r := range in.Egress {
			out.Egress[i] = *r.DeepCopy()
		}
	}
	if in.Types != nil {
		out.Types = make([]string, len(in.Types))
		copy(out.Types, in.Types)
	}
	return out
}

// DeepCopy creates a deep copy of CalicoRule
func (in *CalicoRule) DeepCopy() *CalicoRule {
	if in == nil {
		return nil
	}
	out := new(CalicoRule)
	out.Action = in.Action
	out.Protocol = in.Protocol
	if in.Source != nil {
		out.Source = in.Source.DeepCopy()
	}
	if in.Destination != nil {
		out.Destination = in.Destination.DeepCopy()
	}
	return out
}

// DeepCopy creates a deep copy of CalicoEntityRule
func (in *CalicoEntityRule) DeepCopy() *CalicoEntityRule {
	if in == nil {
		return nil
	}
	out := new(CalicoEntityRule)
	out.Selector = in.Selector
	out.NamespaceSelector = in.NamespaceSelector
	if in.Nets != nil {
		out.Nets = make([]string, len(in.Nets))
		copy(out.Nets, in.Nets)
	}
	if in.NotNets != nil {
		out.NotNets = make([]string, len(in.NotNets))
		copy(out.NotNets, in.NotNets)
	}
	if in.Ports != nil {
		out.Ports = make([]interface{}, len(in.Ports))
		copy(out.Ports, in.Ports)
	}
	return out
}
