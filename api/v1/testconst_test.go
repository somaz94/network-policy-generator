package v1

// Fixture values shared across the api/v1 tests. Mode, policy type, direction
// and protocol values are not repeated here — the tests use the package
// constants declared in networkpolicygenerator_webhook.go.
const (
	nsDefault = "default"
	nsOne     = "ns1"
	nsTwo     = "ns2"

	valueInvalid = "invalid"

	cidr10Slash8  = "10.0.0.0/8"
	cidr10Slash16 = "10.1.0.0/16"
)
