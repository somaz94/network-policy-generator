package policy

import securityv1 "github.com/somaz94/network-policy-generator/api/v1"

// ruleScope is the resolved peer set of one GlobalRule.
type ruleScope struct {
	anywhere   bool
	namespaces []string // pods in these namespaces; used when anywhere is false
}

// resolveScope turns rule.From into the peers to allow for a policy placed in
// policyNamespace. allowedNamespaces with an empty list narrows to the policy's
// own namespace; it never widens to anywhere.
func resolveScope(rule securityv1.GlobalRule, generator *securityv1.NetworkPolicyGenerator, policyNamespace string) ruleScope {
	switch rule.From {
	case FromAllowedNamespaces:
		if allowed := generator.Spec.Policy.AllowedNamespaces; len(allowed) > 0 {
			return ruleScope{namespaces: allowed}
		}
		return ruleScope{namespaces: []string{policyNamespace}}
	case FromSameNamespace:
		return ruleScope{namespaces: []string{policyNamespace}}
	default:
		return ruleScope{anywhere: true}
	}
}
