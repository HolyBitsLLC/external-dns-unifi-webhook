package unifi

import (
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

func TestAdjustEndpointsUniFiIntent(t *testing.T) {
	provider := &UnifiProvider{}

	endpoints := []*endpoint.Endpoint{
		endpoint.NewEndpoint("skip.example.com", "A", "10.0.0.10"),
		endpoint.NewEndpoint("dns.example.com", "A", "10.0.0.20").WithProviderSpecific(providerSpecificUniFiDNS, "true"),
		endpoint.NewEndpoint("pf.example.com", "A", "10.0.0.30").WithProviderSpecific(providerSpecificUniFiPortForward, "443:8443"),
	}

	adjusted, err := provider.AdjustEndpoints(endpoints)
	if err != nil {
		t.Fatalf("AdjustEndpoints() error = %v", err)
	}

	if len(adjusted) != 2 {
		t.Fatalf("AdjustEndpoints() returned %d endpoints, want 2", len(adjusted))
	}

	if adjusted[0].DNSName != "dns.example.com" {
		t.Fatalf("first endpoint DNSName = %q, want dns.example.com", adjusted[0].DNSName)
	}

	if adjusted[1].DNSName != "pf.example.com" {
		t.Fatalf("second endpoint DNSName = %q, want pf.example.com", adjusted[1].DNSName)
	}
}

func TestParsePortForwardMapping(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantErr   bool
		wantSrc   string
		wantDst   string
	}{
		{name: "valid mapping", value: "32400:32400", wantSrc: "32400", wantDst: "32400"},
		{name: "valid with whitespace", value: " 443 : 8443 ", wantSrc: "443", wantDst: "8443"},
		{name: "missing colon", value: "443", wantErr: true},
		{name: "non numeric", value: "abc:8443", wantErr: true},
		{name: "out of range", value: "70000:8443", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping, err := parsePortForwardMapping(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePortForwardMapping(%q) expected error, got nil", tt.value)
				}
				return
			}

			if err != nil {
				t.Fatalf("parsePortForwardMapping(%q) unexpected error: %v", tt.value, err)
			}

			if mapping.srcPort != tt.wantSrc || mapping.dstPort != tt.wantDst {
				t.Fatalf(
					"parsePortForwardMapping(%q) = (%s,%s), want (%s,%s)",
					tt.value,
					mapping.srcPort,
					mapping.dstPort,
					tt.wantSrc,
					tt.wantDst,
				)
			}
		})
	}
}

func TestDesiredPortForwardRule(t *testing.T) {
	ep := endpoint.NewEndpoint("app.example.com", "A", "10.0.12.20").WithProviderSpecific(providerSpecificUniFiPortForward, "443:8443")
	mapping, err := parsePortForwardMapping("443:8443")
	if err != nil {
		t.Fatalf("parsePortForwardMapping() error = %v", err)
	}

	rule, err := desiredPortForwardRule(ep, mapping)
	if err != nil {
		t.Fatalf("desiredPortForwardRule() error = %v", err)
	}

	if rule.DstPort != "443" {
		t.Fatalf("DstPort = %q, want 443", rule.DstPort)
	}

	if rule.FwdPort != "8443" {
		t.Fatalf("FwdPort = %q, want 8443", rule.FwdPort)
	}

	if rule.Fwd != "10.0.12.20" {
		t.Fatalf("Fwd = %q, want 10.0.12.20", rule.Fwd)
	}
}

func TestDesiredPortForwardRuleRejectsNonIPv4Target(t *testing.T) {
	ep := endpoint.NewEndpoint("app.example.com", "A", "lb.internal.example.com")
	mapping, err := parsePortForwardMapping("443:8443")
	if err != nil {
		t.Fatalf("parsePortForwardMapping() error = %v", err)
	}

	_, err = desiredPortForwardRule(ep, mapping)
	if err == nil {
		t.Fatal("desiredPortForwardRule() expected error, got nil")
	}
}
