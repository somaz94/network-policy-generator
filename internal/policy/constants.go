package policy

import "time"

const (
	// Mode constants for spec.mode
	ModeLearning  = "learning"
	ModeEnforcing = "enforcing"

	// Phase constants for status.phase
	PhaseLearning  = "Learning"
	PhaseEnforcing = "Enforcing"

	// Policy type constants
	PolicyTypeAllow = "allow"
	PolicyTypeDeny  = "deny"

	// Traffic direction constants
	DirectionIngress = "ingress"
	DirectionEgress  = "egress"

	// Label keys
	LabelK8sNamespace     = "kubernetes.io/metadata.name"
	LabelCiliumPodNS      = "k8s:io.kubernetes.pod.namespace"
	LabelCiliumK8sApp     = "k8s:k8s-app"
	LabelCiliumKubeDNSApp = "kube-dns"
	LabelCiliumKubeSystem = "kube-system"

	// Network constants
	CIDRAllTraffic = "0.0.0.0/0"
	DNSPort        = 53
	DNSPortStr     = "53"

	// Policy engine types
	EngineKubernetes = "kubernetes"
	EngineCilium     = "cilium"

	// Cilium-specific
	EntityWorld      = "world"
	CiliumAPIVersion = "cilium.io/v2"
	CiliumKind       = "CiliumNetworkPolicy"
	CiliumGroup      = "cilium.io"
	CiliumVersion    = "v2"

	// Policy naming
	PolicyNameSuffix = "-generated"

	// Requeue intervals
	DefaultRequeueInterval = 5 * time.Minute
)

// PolicyName returns the generated policy name for a generator
func PolicyName(generatorName string) string {
	return generatorName + PolicyNameSuffix
}
