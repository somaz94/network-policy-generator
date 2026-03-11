package policy

import (
	"fmt"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PolicyEngine is the interface that both Kubernetes and Cilium policy generators implement
type PolicyEngine interface {
	// GeneratePolicies generates CNI-specific network policies as runtime.Object slices
	GeneratePolicies(generator *securityv1.NetworkPolicyGenerator) ([]runtime.Object, error)

	// EngineName returns the name of the policy engine (e.g., "kubernetes", "cilium")
	EngineName() string
}

// NewPolicyEngine creates the appropriate PolicyEngine based on the engine type
func NewPolicyEngine(engineType string) (PolicyEngine, error) {
	switch engineType {
	case "kubernetes", "":
		return NewKubernetesEngine(), nil
	case "cilium":
		return NewCiliumEngine(), nil
	default:
		return nil, fmt.Errorf("unsupported policy engine: %s", engineType)
	}
}
