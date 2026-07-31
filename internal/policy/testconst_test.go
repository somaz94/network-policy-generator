package policy

// Fixture values shared across the policy engine tests. Contract values —
// policy types, engines, directions, protocols — are not repeated here; the
// tests use the exported constants from constants.go directly.
const (
	nsDefault  = "default"
	nsTest     = "test-namespace"
	nsOne      = "ns1"
	nsTwo      = "ns2"
	nsAllowed1 = "allowed-ns1"
	nsAllowed2 = "allowed-ns2"

	nameTest       = "test"
	nameTestPolicy = "test-policy"

	labelApp           = "app"
	labelTier          = "tier"
	labelValueWeb      = "web"
	labelValueFrontend = "frontend"

	namedPortHTTP = "http"

	cidr10Slash8   = "10.0.0.0/8"
	cidr192Slash24 = "192.168.1.0/24"
	cidrHost192    = "192.168.1.100/32"
)
