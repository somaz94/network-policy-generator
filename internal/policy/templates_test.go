package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestGetTemplate(t *testing.T) {
	t.Run("returns nil for unknown template", func(t *testing.T) {
		tmpl := GetTemplate("nonexistent")
		assert.Nil(t, tmpl)
	})

	t.Run("returns zero-trust template", func(t *testing.T) {
		tmpl := GetTemplate(TemplateZeroTrust)
		require.NotNil(t, tmpl)
		assert.Equal(t, TemplateZeroTrust, tmpl.Name)
	})

	t.Run("returns web-app template", func(t *testing.T) {
		tmpl := GetTemplate(TemplateWebApp)
		require.NotNil(t, tmpl)
		assert.Equal(t, TemplateWebApp, tmpl.Name)
	})

	t.Run("returns backend-api template", func(t *testing.T) {
		tmpl := GetTemplate(TemplateBackendAPI)
		require.NotNil(t, tmpl)
		assert.Equal(t, TemplateBackendAPI, tmpl.Name)
	})

	t.Run("returns database template", func(t *testing.T) {
		tmpl := GetTemplate(TemplateDatabase)
		require.NotNil(t, tmpl)
		assert.Equal(t, TemplateDatabase, tmpl.Name)
	})

	t.Run("returns monitoring template", func(t *testing.T) {
		tmpl := GetTemplate(TemplateMonitoring)
		require.NotNil(t, tmpl)
		assert.Equal(t, TemplateMonitoring, tmpl.Name)
	})
}

func TestListTemplateNames(t *testing.T) {
	names := ListTemplateNames()
	assert.Len(t, names, 5)
	assert.Contains(t, names, TemplateZeroTrust)
	assert.Contains(t, names, TemplateWebApp)
	assert.Contains(t, names, TemplateBackendAPI)
	assert.Contains(t, names, TemplateDatabase)
	assert.Contains(t, names, TemplateMonitoring)
}

func TestTemplateApply(t *testing.T) {
	t.Run("zero-trust sets deny type", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGeneratorSpec{
			Policy: securityv1.PolicyConfig{Type: "allow"},
		}
		tmpl := GetTemplate(TemplateZeroTrust)
		tmpl.Apply(spec)
		assert.Equal(t, PolicyTypeDeny, spec.Policy.Type)
	})

	t.Run("web-app adds HTTP/HTTPS rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGeneratorSpec{}
		tmpl := GetTemplate(TemplateWebApp)
		tmpl.Apply(spec)

		assert.Equal(t, PolicyTypeDeny, spec.Policy.Type)
		require.NotEmpty(t, spec.GlobalRules)

		// Should have port 80 ingress, 443 ingress, 443 egress
		hasPort80Ingress := false
		hasPort443Ingress := false
		hasPort443Egress := false
		for _, r := range spec.GlobalRules {
			if r.Port == 80 && r.Direction == DirectionIngress {
				hasPort80Ingress = true
			}
			if r.Port == 443 && r.Direction == DirectionIngress {
				hasPort443Ingress = true
			}
			if r.Port == 443 && r.Direction == DirectionEgress {
				hasPort443Egress = true
			}
		}
		assert.True(t, hasPort80Ingress, "should have port 80 ingress")
		assert.True(t, hasPort443Ingress, "should have port 443 ingress")
		assert.True(t, hasPort443Egress, "should have port 443 egress")
	})

	t.Run("backend-api adds API port rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGeneratorSpec{}
		tmpl := GetTemplate(TemplateBackendAPI)
		tmpl.Apply(spec)

		ports := make(map[int32]bool)
		for _, r := range spec.GlobalRules {
			if r.Direction == DirectionIngress {
				ports[r.Port] = true
			}
		}
		assert.True(t, ports[8080], "should have port 8080")
		assert.True(t, ports[8443], "should have port 8443")
		assert.True(t, ports[9090], "should have port 9090")
	})

	t.Run("database adds DB port rules", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGeneratorSpec{}
		tmpl := GetTemplate(TemplateDatabase)
		tmpl.Apply(spec)

		ports := make(map[int32]bool)
		for _, r := range spec.GlobalRules {
			if r.Direction == DirectionIngress {
				ports[r.Port] = true
			}
		}
		assert.True(t, ports[3306], "should have MySQL port")
		assert.True(t, ports[5432], "should have PostgreSQL port")
		assert.True(t, ports[6379], "should have Redis port")
		assert.True(t, ports[27017], "should have MongoDB port")
	})

	t.Run("monitoring adds Prometheus ports", func(t *testing.T) {
		spec := &securityv1.NetworkPolicyGeneratorSpec{}
		tmpl := GetTemplate(TemplateMonitoring)
		tmpl.Apply(spec)

		ports := make(map[int32]bool)
		for _, r := range spec.GlobalRules {
			if r.Direction == DirectionIngress {
				ports[r.Port] = true
			}
		}
		assert.True(t, ports[9090], "should have Prometheus port")
		assert.True(t, ports[9100], "should have node-exporter port")
	})
}

func TestMergeGlobalRules(t *testing.T) {
	t.Run("user rules take precedence", func(t *testing.T) {
		userRules := []securityv1.GlobalRule{
			{Type: "deny", Port: 80, Protocol: "TCP", Direction: DirectionIngress},
		}
		templateRules := []securityv1.GlobalRule{
			{Type: "allow", Port: 80, Protocol: "TCP", Direction: DirectionIngress},
			{Type: "allow", Port: 443, Protocol: "TCP", Direction: DirectionIngress},
		}

		result := mergeGlobalRules(userRules, templateRules...)

		// User's deny rule for port 80 should win over template's allow
		require.Len(t, result, 2) // port 80 (user) + port 443 (template)
		assert.Equal(t, "deny", result[0].Type)
		assert.Equal(t, int32(80), result[0].Port)
		assert.Equal(t, int32(443), result[1].Port)
	})

	t.Run("empty user rules uses all template rules", func(t *testing.T) {
		templateRules := []securityv1.GlobalRule{
			{Type: "allow", Port: 80, Protocol: "TCP", Direction: DirectionIngress},
			{Type: "allow", Port: 443, Protocol: "TCP", Direction: DirectionEgress},
		}

		result := mergeGlobalRules(nil, templateRules...)
		assert.Len(t, result, 2)
	})

	t.Run("no template rules keeps user rules", func(t *testing.T) {
		userRules := []securityv1.GlobalRule{
			{Type: "allow", Port: 8080, Protocol: "TCP", Direction: DirectionIngress},
		}

		result := mergeGlobalRules(userRules)
		assert.Len(t, result, 1)
		assert.Equal(t, int32(8080), result[0].Port)
	})

	t.Run("named port dedup", func(t *testing.T) {
		userRules := []securityv1.GlobalRule{
			{Type: "allow", NamedPort: "http", Protocol: "TCP", Direction: DirectionIngress},
		}
		templateRules := []securityv1.GlobalRule{
			{Type: "allow", NamedPort: "http", Protocol: "TCP", Direction: DirectionIngress},
		}

		result := mergeGlobalRules(userRules, templateRules...)
		assert.Len(t, result, 1) // deduped
	})
}

func TestTemplateWithUserRulesPreserved(t *testing.T) {
	spec := &securityv1.NetworkPolicyGeneratorSpec{
		GlobalRules: []securityv1.GlobalRule{
			{Type: "allow", Port: 9999, Protocol: "TCP", Direction: DirectionIngress},
		},
	}

	tmpl := GetTemplate(TemplateWebApp)
	tmpl.Apply(spec)

	// User's custom rule should be preserved alongside template rules
	hasUserRule := false
	for _, r := range spec.GlobalRules {
		if r.Port == 9999 {
			hasUserRule = true
		}
	}
	assert.True(t, hasUserRule, "user's custom rule should be preserved")
	assert.Greater(t, len(spec.GlobalRules), 1, "should have template rules too")
}
