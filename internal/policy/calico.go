package policy

import (
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// CalicoEngine generates Calico NetworkPolicy resources
type CalicoEngine struct{}

// NewCalicoEngine creates a new Calico policy engine
func NewCalicoEngine() *CalicoEngine {
	return &CalicoEngine{}
}

// EngineName returns "calico"
func (e *CalicoEngine) EngineName() string {
	return EngineCalico
}

// GeneratePolicies generates CalicoNetworkPolicy objects
func (e *CalicoEngine) GeneratePolicies(generator *securityv1.NetworkPolicyGenerator) ([]runtime.Object, error) {
	order := CalicoDefaultOrder
	selector := "all()"
	if len(generator.Spec.Policy.PodSelector) > 0 {
		selector = buildCalicoSelector(generator.Spec.Policy.PodSelector)
	}

	basePolicy := &CalicoNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: CalicoAPIVersion,
			Kind:       CalicoKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyName(generator.Name),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: generator.APIVersion,
					Kind:       generator.Kind,
					Name:       generator.Name,
					UID:        generator.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: &CalicoNetworkPolicySpec{
			Order:    &order,
			Selector: selector,
			Types:    []string{"Ingress", "Egress"},
		},
	}

	var policies []runtime.Object
	if generator.Spec.Policy.Type == PolicyTypeAllow {
		policies = e.generateAllowPolicies(basePolicy, generator)
	} else {
		policies = e.generateDenyPolicies(basePolicy, generator)
	}

	// Add DNS egress rule to all policies
	for _, obj := range policies {
		calicoPolicy := obj.(*CalicoNetworkPolicy)
		calicoPolicy.Spec.Egress = append(calicoPolicy.Spec.Egress, dnsEgressRuleCalico())
	}

	e.applyGlobalRules(policies, generator)
	e.applyCIDRRules(policies, generator.Spec.CIDRRules)

	return policies, nil
}

// generateDenyPolicies creates policies for deny type (allow only specified namespaces)
func (e *CalicoEngine) generateDenyPolicies(basePolicy *CalicoNetworkPolicy, generator *securityv1.NetworkPolicyGenerator) []runtime.Object {
	policy := basePolicy.DeepCopyObject().(*CalicoNetworkPolicy)
	policy.Namespace = generator.Namespace

	if len(generator.Spec.Policy.AllowedNamespaces) > 0 {
		nsSelector := buildCalicoNamespaceSelector(generator.Spec.Policy.AllowedNamespaces)
		policy.Spec.Ingress = []CalicoRule{{
			Action: CalicoActionAllow,
			Source: &CalicoEntityRule{NamespaceSelector: nsSelector},
		}}
		policy.Spec.Egress = []CalicoRule{{
			Action:      CalicoActionAllow,
			Destination: &CalicoEntityRule{NamespaceSelector: nsSelector},
		}}
	}

	return []runtime.Object{policy}
}

// generateAllowPolicies creates policies for allow type (deny in specified namespaces)
func (e *CalicoEngine) generateAllowPolicies(basePolicy *CalicoNetworkPolicy, generator *securityv1.NetworkPolicyGenerator) []runtime.Object {
	var policies []runtime.Object

	if len(generator.Spec.Policy.DeniedNamespaces) == 0 {
		return policies
	}

	for _, ns := range generator.Spec.Policy.DeniedNamespaces {
		policy := basePolicy.DeepCopyObject().(*CalicoNetworkPolicy)
		policy.Namespace = ns

		nsSelector := buildCalicoNamespaceSelector(generator.Spec.Policy.DeniedNamespaces)
		policy.Spec.Ingress = []CalicoRule{{
			Action: CalicoActionDeny,
			Source: &CalicoEntityRule{NamespaceSelector: nsSelector},
		}}
		policy.Spec.Egress = []CalicoRule{{
			Action:      CalicoActionDeny,
			Destination: &CalicoEntityRule{NamespaceSelector: nsSelector},
		}}

		policies = append(policies, policy)
	}

	return policies
}

// applyGlobalRules adds global rules to all Calico policies. Anywhere leaves
// the peer side unselected, which Calico reads as any source or destination.
func (e *CalicoEngine) applyGlobalRules(policies []runtime.Object, generator *securityv1.NetworkPolicyGenerator) {
	for _, obj := range policies {
		calicoPolicy := obj.(*CalicoNetworkPolicy)
		for _, rule := range generator.Spec.GlobalRules {
			calicoRule := CalicoRule{
				Action:   CalicoActionAllow,
				Protocol: rule.Protocol,
			}
			deny := rule.Type == PolicyTypeDeny
			if deny {
				calicoRule.Action = CalicoActionDeny
			}
			ports := []interface{}{calicoGlobalRulePort(rule)}
			var peer *CalicoEntityRule
			if scope := resolveScope(rule, generator, calicoPolicy.Namespace); !scope.anywhere {
				peer = &CalicoEntityRule{NamespaceSelector: buildCalicoNamespaceSelector(scope.namespaces)}
			}

			switch rule.Direction {
			case DirectionIngress:
				calicoRule.Source = peer
				calicoRule.Destination = &CalicoEntityRule{Ports: ports}
				calicoPolicy.Spec.Ingress = addCalicoRule(calicoPolicy.Spec.Ingress, calicoRule, deny)
			case DirectionEgress:
				dest := &CalicoEntityRule{Ports: ports}
				if peer != nil {
					dest.NamespaceSelector = peer.NamespaceSelector
				}
				calicoRule.Destination = dest
				calicoPolicy.Spec.Egress = addCalicoRule(calicoPolicy.Spec.Egress, calicoRule, deny)
			}
		}
	}
}

// addCalicoRule appends an allow rule, or puts a deny rule ahead of every rule
// already present: Calico stops at the first rule that matches.
func addCalicoRule(rules []CalicoRule, rule CalicoRule, deny bool) []CalicoRule {
	if !deny {
		return append(rules, rule)
	}
	return append([]CalicoRule{rule}, rules...)
}

// applyCIDRRules adds CIDR-based rules to all Calico policies
func (e *CalicoEngine) applyCIDRRules(policies []runtime.Object, cidrRules []securityv1.CIDRRule) {
	if cidrRules == nil {
		return
	}

	for _, obj := range policies {
		calicoPolicy := obj.(*CalicoNetworkPolicy)
		for _, rule := range cidrRules {
			entity := &CalicoEntityRule{
				Nets:    []string{rule.CIDR},
				NotNets: rule.Except,
			}

			switch rule.Direction {
			case DirectionIngress:
				calicoPolicy.Spec.Ingress = append(calicoPolicy.Spec.Ingress, CalicoRule{
					Action: CalicoActionAllow,
					Source: entity,
				})
			case DirectionEgress:
				calicoPolicy.Spec.Egress = append(calicoPolicy.Spec.Egress, CalicoRule{
					Action:      CalicoActionAllow,
					Destination: entity,
				})
			}
		}
	}
}

// buildCalicoSelector converts a label map to a Calico selector expression
func buildCalicoSelector(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s == '%s'", k, v))
	}
	return strings.Join(parts, " && ")
}

// buildCalicoNamespaceSelector creates a namespace selector expression for Calico
func buildCalicoNamespaceSelector(namespaces []string) string {
	if len(namespaces) == 1 {
		return fmt.Sprintf("projectcalico.org/name == '%s'", namespaces[0])
	}
	quoted := make([]string, len(namespaces))
	for i, ns := range namespaces {
		quoted[i] = fmt.Sprintf("'%s'", ns)
	}
	return fmt.Sprintf("projectcalico.org/name in { %s }", strings.Join(quoted, ", "))
}

// calicoGlobalRulePort returns the port value for a GlobalRule
func calicoGlobalRulePort(rule securityv1.GlobalRule) interface{} {
	if rule.NamedPort != "" {
		return rule.NamedPort
	}
	return strconv.Itoa(int(rule.Port))
}

// dnsEgressRuleCalico creates a Calico egress rule allowing DNS resolution
func dnsEgressRuleCalico() CalicoRule {
	return CalicoRule{
		Action:   CalicoActionAllow,
		Protocol: ProtocolUDP,
		Destination: &CalicoEntityRule{
			NamespaceSelector: "projectcalico.org/name == 'kube-system'",
			Selector:          "k8s-app == 'kube-dns'",
			Ports:             []interface{}{DNSPort},
		},
	}
}

// Ensure CalicoEngine implements PolicyEngine (compile-time check)
var _ PolicyEngine = (*CalicoEngine)(nil)
