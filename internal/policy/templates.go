package policy

import (
	"strconv"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// TemplateName constants
const (
	TemplateZeroTrust  = "zero-trust"
	TemplateWebApp     = "web-app"
	TemplateBackendAPI = "backend-api"
	TemplateDatabase   = "database"
	TemplateMonitoring = "monitoring"
)

// PolicyTemplate defines a reusable policy template
type PolicyTemplate struct {
	// Name is the template identifier
	Name string
	// Description explains what the template does
	Description string
	// Apply populates the generator spec with template defaults
	Apply func(spec *securityv1.NetworkPolicyGeneratorSpec)
}

// Templates is the registry of all built-in policy templates
var Templates = map[string]PolicyTemplate{
	TemplateZeroTrust: {
		Name:        TemplateZeroTrust,
		Description: "Deny all traffic by default, allow only DNS egress. Suitable for high-security namespaces.",
		Apply: func(spec *securityv1.NetworkPolicyGeneratorSpec) {
			spec.Policy.Type = PolicyTypeDeny
			// No allowedNamespaces = deny all namespace traffic
			spec.GlobalRules = mergeGlobalRules(spec.GlobalRules) // keep user-defined rules
		},
	},
	TemplateWebApp: {
		Name:        TemplateWebApp,
		Description: "Allow HTTP/HTTPS ingress from anywhere, DNS egress. Typical for frontend/web services.",
		Apply: func(spec *securityv1.NetworkPolicyGeneratorSpec) {
			spec.Policy.Type = PolicyTypeDeny
			spec.GlobalRules = mergeGlobalRules(spec.GlobalRules,
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 80, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 443, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 443, Protocol: ProtocolTCP, Direction: DirectionEgress},
			)
		},
	},
	TemplateBackendAPI: {
		Name:        TemplateBackendAPI,
		Description: "Allow ingress on common API ports (8080, 8443, 9090), restrict egress to DNS and HTTPS.",
		Apply: func(spec *securityv1.NetworkPolicyGeneratorSpec) {
			spec.Policy.Type = PolicyTypeDeny
			spec.GlobalRules = mergeGlobalRules(spec.GlobalRules,
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 8080, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 8443, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 9090, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 443, Protocol: ProtocolTCP, Direction: DirectionEgress},
			)
		},
	},
	TemplateDatabase: {
		Name:        TemplateDatabase,
		Description: "Allow ingress only on database ports (3306, 5432, 6379, 27017), deny all egress except DNS.",
		Apply: func(spec *securityv1.NetworkPolicyGeneratorSpec) {
			spec.Policy.Type = PolicyTypeDeny
			spec.GlobalRules = mergeGlobalRules(spec.GlobalRules,
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 3306, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 5432, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 6379, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 27017, Protocol: ProtocolTCP, Direction: DirectionIngress},
			)
		},
	},
	TemplateMonitoring: {
		Name:        TemplateMonitoring,
		Description: "Allow Prometheus scraping (9090, 9100) and common monitoring ports. Suitable for observability stacks.",
		Apply: func(spec *securityv1.NetworkPolicyGeneratorSpec) {
			spec.Policy.Type = PolicyTypeDeny
			spec.GlobalRules = mergeGlobalRules(spec.GlobalRules,
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 9090, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 9100, Protocol: ProtocolTCP, Direction: DirectionIngress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 9090, Protocol: ProtocolTCP, Direction: DirectionEgress},
				securityv1.GlobalRule{Type: PolicyTypeAllow, Port: 443, Protocol: ProtocolTCP, Direction: DirectionEgress},
			)
		},
	},
}

// GetTemplate returns a policy template by name, or nil if not found
func GetTemplate(name string) *PolicyTemplate {
	t, ok := Templates[name]
	if !ok {
		return nil
	}
	return &t
}

// ListTemplateNames returns all available template names
func ListTemplateNames() []string {
	names := make([]string, 0, len(Templates))
	for name := range Templates {
		names = append(names, name)
	}
	return names
}

// mergeGlobalRules merges template rules with user-defined rules (user rules take precedence)
func mergeGlobalRules(userRules []securityv1.GlobalRule, templateRules ...securityv1.GlobalRule) []securityv1.GlobalRule {
	// Start with template rules, then append user rules (user overrides)
	seen := make(map[string]bool)
	var result []securityv1.GlobalRule

	// User rules first (higher priority)
	for _, r := range userRules {
		key := globalRuleKey(r)
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}

	// Template rules (only add if not already defined by user)
	for _, r := range templateRules {
		key := globalRuleKey(r)
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}

	return result
}

// globalRuleKey generates a dedup key for a global rule
func globalRuleKey(r securityv1.GlobalRule) string {
	if r.NamedPort != "" {
		return r.Direction + "/" + r.Protocol + "/" + r.NamedPort
	}
	return r.Direction + "/" + r.Protocol + "/" + strconv.Itoa(int(r.Port))
}
