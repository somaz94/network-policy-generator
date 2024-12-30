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

// NetworkPolicyGeneratorSpec defines the desired state of NetworkPolicyGenerator
type NetworkPolicyGeneratorSpec struct {
	// Mode specifies the operation mode: "learning" or "enforcing"
	// +kubebuilder:validation:Enum=learning;enforcing
	Mode string `json:"mode,omitempty"`

	// Duration specifies how long to analyze traffic in learning mode
	Duration metav1.Duration `json:"duration,omitempty"`

	// Policy defines the main policy configuration
	Policy PolicyConfig `json:"policy"`

	// GlobalRules defines the global traffic rules
	// +optional
	GlobalRules []GlobalRule `json:"globalRules,omitempty"`
}

// PolicyConfig defines the main policy configuration
type PolicyConfig struct {
	// Type defines the policy type (allow/deny)
	// +kubebuilder:validation:Enum=allow;deny
	Type string `json:"type"`

	// AllowedNamespaces lists namespaces that are allowed when policy type is deny
	// +optional
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`

	// DeniedNamespaces lists namespaces that are denied when policy type is allow
	// +optional
	DeniedNamespaces []string `json:"deniedNamespaces,omitempty"`
}

// GlobalRule defines a single traffic rule
type GlobalRule struct {
	// Type defines whether to allow or deny this rule
	// +kubebuilder:validation:Enum=allow;deny
	Type string `json:"type"`

	// Port number
	Port int32 `json:"port"`

	// Protocol (TCP/UDP)
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`

	// Direction of the traffic (ingress/egress)
	// +kubebuilder:validation:Enum=ingress;egress
	Direction string `json:"direction"`
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
//+kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
//+kubebuilder:printcolumn:name="LastAnalyzed",type="string",JSONPath=".status.lastAnalyzed"
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

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
