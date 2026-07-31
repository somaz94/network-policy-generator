package controller

// Fixture values shared across the controller tests. Contract values — modes,
// phases, policy types, engines, directions, protocols — are not repeated
// here; the tests reference internal/policy constants directly.
const (
	nsDefault = "default"
	nsOne     = "ns1"
	nsA       = "ns-a"

	nameModeChangeTest = "mode-change-test"

	namedPortHTTP = "http"

	// Plural resource names as they appear in a GroupResource.
	resourceNetworkPolicies       = "networkpolicies"
	resourceCiliumNetworkPolicies = "ciliumnetworkpolicies"
)
