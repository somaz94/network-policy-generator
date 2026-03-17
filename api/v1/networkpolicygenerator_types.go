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

	// PolicyEngine specifies the CNI-specific policy engine to use
	// "kubernetes" generates standard NetworkPolicy (networking.k8s.io/v1)
	// "cilium" generates CiliumNetworkPolicy (cilium.io/v2)
	// +kubebuilder:validation:Enum=kubernetes;cilium
	// +kubebuilder:default=kubernetes
	// +optional
	PolicyEngine string `json:"policyEngine,omitempty"`

	// DryRun when true, generates policies without applying them
	// Generated policies are stored in status.generatedPolicies
	// +optional
	DryRun bool `json:"dryRun,omitempty"`

	// Policy defines the main policy configuration
	Policy PolicyConfig `json:"policy"`

	// GlobalRules defines the global traffic rules
	// +optional
	GlobalRules []GlobalRule `json:"globalRules,omitempty"`

	// CIDRRules defines CIDR-based traffic rules for external IP ranges
	// +optional
	CIDRRules []CIDRRule `json:"cidrRules,omitempty"`
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

	// PodSelector restricts policy to pods matching these labels
	// If empty, applies to all pods in the namespace
	// +optional
	PodSelector map[string]string `json:"podSelector,omitempty"`
}

// GlobalRule defines a single traffic rule
type GlobalRule struct {
	// Type defines whether to allow or deny this rule
	// +kubebuilder:validation:Enum=allow;deny
	Type string `json:"type"`

	// Port number (1-65535). Either port or namedPort must be specified.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`

	// NamedPort is the port name (e.g., "http", "grpc") as an alternative to numeric port
	// +optional
	NamedPort string `json:"namedPort,omitempty"`

	// Protocol (TCP/UDP)
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`

	// Direction of the traffic (ingress/egress)
	// +kubebuilder:validation:Enum=ingress;egress
	Direction string `json:"direction"`
}

// CIDRRule defines a CIDR-based traffic rule for external IP ranges
type CIDRRule struct {
	// CIDR is the IP address range (e.g., "10.0.0.0/8", "192.168.1.0/24")
	CIDR string `json:"cidr"`

	// Except is a list of CIDRs to exclude from the rule
	// +optional
	Except []string `json:"except,omitempty"`

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

	// GeneratedPolicies contains the YAML representation of generated policies (populated in dry-run mode)
	// +optional
	GeneratedPolicies []string `json:"generatedPolicies,omitempty"`

	// PolicyDiff contains the diff between the current and previously applied policies
	// +optional
	PolicyDiff []PolicyDiffEntry `json:"policyDiff,omitempty"`

	// AppliedPoliciesCount is the number of currently applied policies
	// +optional
	AppliedPoliciesCount int `json:"appliedPoliciesCount,omitempty"`
}

// PolicyDiffEntry represents a single diff entry for policy audit
type PolicyDiffEntry struct {
	// PolicyName is the name of the policy
	PolicyName string `json:"policyName"`

	// Namespace is the namespace of the policy
	Namespace string `json:"namespace"`

	// Action is the type of change: Created, Updated, Unchanged
	Action string `json:"action"`

	// Timestamp is when the change was detected
	Timestamp metav1.Time `json:"timestamp"`
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
