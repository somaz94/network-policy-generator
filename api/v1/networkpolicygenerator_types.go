/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GlobalRule defines a traffic rule
type GlobalRule struct {
	// Port number
	Port int32 `json:"port"`

	// Protocol (TCP/UDP)
	Protocol string `json:"protocol"`
}

// GlobalRuleSet defines a set of ingress and egress rules
type GlobalRuleSet struct {
	// Enabled indicates whether this rule set is active
	Enabled bool `json:"enabled"`

	// Ingress rules to be applied globally
	// +optional
	Ingress []GlobalRule `json:"ingress,omitempty"`

	// Egress rules to be applied globally
	// +optional
	Egress []GlobalRule `json:"egress,omitempty"`
}

// DefaultPolicyType defines the type of default policy
// +kubebuilder:validation:Enum=allow;deny
type DefaultPolicyType string

const (
	// PolicyAllow allows all traffic by default
	PolicyAllow DefaultPolicyType = "allow"
	// PolicyDeny denies all traffic by default
	PolicyDeny DefaultPolicyType = "deny"
)

// DirectionPolicy defines the policy for a specific direction (ingress/egress)
type DirectionPolicy struct {
	// FollowDefault indicates whether to follow the default policy
	// +optional
	FollowDefault bool `json:"followDefault"`

	// Policy defines the policy type when not following default
	// +optional
	Policy DefaultPolicyType `json:"policy,omitempty"`
}

// DefaultPolicy defines the default network policy configuration
type DefaultPolicy struct {
	// Type defines the default policy type (allow/deny)
	Type DefaultPolicyType `json:"type"`

	// Ingress defines the ingress-specific policy
	// +optional
	Ingress DirectionPolicy `json:"ingress,omitempty"`

	// Egress defines the egress-specific policy
	// +optional
	Egress DirectionPolicy `json:"egress,omitempty"`
}

// NetworkPolicyGeneratorSpec defines the desired state of NetworkPolicyGenerator
type NetworkPolicyGeneratorSpec struct {
	// Mode specifies the operation mode: "learning" or "enforcing"
	Mode string `json:"mode,omitempty"`

	// Duration specifies how long to analyze traffic in learning mode
	Duration metav1.Duration `json:"duration,omitempty"`

	// DefaultPolicy defines the default network policy configuration
	DefaultPolicy DefaultPolicy `json:"defaultPolicy"`

	// AllowedNamespaces lists namespaces that are allowed to communicate when default policy is deny
	// +optional
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`

	// DeniedNamespaces lists namespaces that are denied to communicate when default policy is allow
	// +optional
	DeniedNamespaces []string `json:"deniedNamespaces,omitempty"`

	// GlobalAllowRules defines traffic rules that should be allowed globally
	// +optional
	GlobalAllowRules *GlobalRuleSet `json:"globalAllowRules,omitempty"`

	// GlobalDenyRules defines traffic rules that should be denied globally
	// +optional
	GlobalDenyRules *GlobalRuleSet `json:"globalDenyRules,omitempty"`
}

// NetworkPolicyGeneratorStatus defines the observed state of NetworkPolicyGenerator
type NetworkPolicyGeneratorStatus struct {
	// Phase represents the current phase of the generator: Learning, Analyzing, or Enforcing
	Phase string `json:"phase,omitempty"`

	// LastAnalyzed is the timestamp of when traffic was last analyzed
	LastAnalyzed metav1.Time `json:"lastAnalyzed,omitempty"`

	// ObservedTraffic contains the list of observed traffic patterns
	ObservedTraffic []TrafficFlow `json:"observedTraffic,omitempty"`
}

// TrafficFlow represents a single observed traffic pattern
type TrafficFlow struct {
	// Source namespace and pod information
	SourceNamespace string `json:"sourceNamespace,omitempty"`
	SourcePod       string `json:"sourcePod,omitempty"`

	// Destination namespace and pod information
	DestNamespace string `json:"destNamespace,omitempty"`
	DestPod       string `json:"destPod,omitempty"`

	// Protocol and port information
	Protocol string `json:"protocol,omitempty"`
	Port     int32  `json:"port,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// NetworkPolicyGenerator is the Schema for the networkpolicygenerators API
type NetworkPolicyGenerator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkPolicyGeneratorSpec   `json:"spec,omitempty"`
	Status NetworkPolicyGeneratorStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkPolicyGeneratorList contains a list of NetworkPolicyGenerator
type NetworkPolicyGeneratorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkPolicyGenerator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkPolicyGenerator{}, &NetworkPolicyGeneratorList{})
}
