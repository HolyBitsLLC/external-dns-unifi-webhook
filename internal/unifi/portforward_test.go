package unifi

import (
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

func TestAdjustEndpointsUniFiIntent(t *testing.T) {
	p := &UnifiProvider{}

	endpoints := []*endpoint.Endpoint{
		endpoint.NewEndpoint("skip.example.com", recordTypeA, "10.0.0.10"),
		endpoint.NewEndpoint("dns.example.com", recordTypeA, "10.0.0.20").
			WithProviderSpecific(providerSpecificUniFiDNS, "true"),
		endpoint.NewEndpoint("pf.example.com", recordTypeA, "10.0.0.30").
			WithProviderSpecific(providerSpecificUniFiPortForward, "443:8443"),
	}

	adjusted, err := p.AdjustEndpoints(endpoints)
	if err != nil {
		t.Fatalf("AdjustEndpoints() error = %v", err)
	}

	if len(adjusted) != 2 {
		t.Fatalf("AdjustEndpoints() returned %d endpoints, want 2", len(adjusted))
	}
	if adjusted[0].DNSName != "dns.example.com" {
		t.Errorf("first endpoint DNSName = %q, want dns.example.com", adjusted[0].DNSName)
	}
	if adjusted[1].DNSName != "pf.example.com" {
		t.Errorf("second endpoint DNSName = %q, want pf.example.com", adjusted[1].DNSName)
	}
}

// A batch where nothing opts in must keep every endpoint. Returning an empty
// desired set there would delete every record on the site under --policy=sync.
func TestAdjustEndpointsKeepsEverythingWithoutIntent(t *testing.T) {
	p := &UnifiProvider{}

	endpoints := []*endpoint.Endpoint{
		endpoint.NewEndpoint("a.example.com", recordTypeA, "10.0.0.10"),
		endpoint.NewEndpoint("b.example.com", recordTypeA, "10.0.0.11"),
	}

	adjusted, err := p.AdjustEndpoints(endpoints)
	if err != nil {
		t.Fatalf("AdjustEndpoints() error = %v", err)
	}

	if len(adjusted) != len(endpoints) {
		t.Fatalf("AdjustEndpoints() returned %d endpoints, want %d", len(adjusted), len(endpoints))
	}
}

// The TTL canonicalization from #229 still applies to the endpoints that are
// kept, so an opted-in TXT record does not churn.
func TestAdjustEndpointsStillClearsUnmanagedTTL(t *testing.T) {
	p := &UnifiProvider{}

	ep := endpoint.NewEndpointWithTTL("txt.example.com", recordTypeTXT, endpoint.TTL(300), "value").
		WithProviderSpecific(providerSpecificUniFiDNS, "true")

	adjusted, err := p.AdjustEndpoints([]*endpoint.Endpoint{ep})
	if err != nil {
		t.Fatalf("AdjustEndpoints() error = %v", err)
	}

	if len(adjusted) != 1 {
		t.Fatalf("AdjustEndpoints() returned %d endpoints, want 1", len(adjusted))
	}
	if adjusted[0].RecordTTL != 0 {
		t.Errorf("RecordTTL = %d, want 0", adjusted[0].RecordTTL)
	}
}

func TestParsePortForwardMapping(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
		wantSrc string
		wantDst string
	}{
		{name: "valid mapping", value: "32400:32400", wantSrc: "32400", wantDst: "32400"},
		{name: "valid with whitespace", value: " 443 : 8443 ", wantSrc: "443", wantDst: "8443"},
		{name: "missing colon", value: "443", wantErr: true},
		{name: "too many separators", value: "443:8443:9000", wantErr: true},
		{name: "non numeric", value: "abc:8443", wantErr: true},
		{name: "out of range", value: "70000:8443", wantErr: true},
		{name: "zero port", value: "0:8443", wantErr: true},
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
				t.Errorf("parsePortForwardMapping(%q) = (%s,%s), want (%s,%s)",
					tt.value, mapping.srcPort, mapping.dstPort, tt.wantSrc, tt.wantDst)
			}
		})
	}
}

func TestDesiredPortForwardRule(t *testing.T) {
	ep := endpoint.NewEndpoint("app.example.com", recordTypeA, "10.0.12.20").
		WithProviderSpecific(providerSpecificUniFiPortForward, "443:8443")

	mapping, err := parsePortForwardMapping("443:8443")
	if err != nil {
		t.Fatalf("parsePortForwardMapping() error = %v", err)
	}

	rule, err := desiredPortForwardRule(ep, mapping)
	if err != nil {
		t.Fatalf("desiredPortForwardRule() error = %v", err)
	}

	if rule.Name != "extdns-app-example-com-443-8443" {
		t.Errorf("Name = %q, want extdns-app-example-com-443-8443", rule.Name)
	}
	if rule.DstPort != "443" {
		t.Errorf("DstPort = %q, want 443", rule.DstPort)
	}
	if rule.FwdPort != "8443" {
		t.Errorf("FwdPort = %q, want 8443", rule.FwdPort)
	}
	if rule.Fwd != "10.0.12.20" {
		t.Errorf("Fwd = %q, want 10.0.12.20", rule.Fwd)
	}
}

func TestDesiredPortForwardRuleRejectsNonIPv4Target(t *testing.T) {
	ep := endpoint.NewEndpoint("app.example.com", recordTypeA, "lb.internal.example.com").
		WithProviderSpecific(providerSpecificUniFiPortForward, "443:8443")

	mapping, err := parsePortForwardMapping("443:8443")
	if err != nil {
		t.Fatalf("parsePortForwardMapping() error = %v", err)
	}

	if _, err := desiredPortForwardRule(ep, mapping); err == nil {
		t.Fatal("desiredPortForwardRule() expected error, got nil")
	}
}

func TestNormalizedRuleName(t *testing.T) {
	tests := []struct {
		name    string
		dnsName string
		mapping portForwardMapping
		want    string
	}{
		{"dots and case", "App.Example.COM.", portForwardMapping{"443", "8443"}, "extdns-app-example-com-443-8443"},
		{"underscores", "a_b.example.com", portForwardMapping{"1", "2"}, "extdns-a-b-example-com-1-2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizedRuleName(tt.dnsName, tt.mapping); got != tt.want {
				t.Errorf("normalizedRuleName(%q) = %q, want %q", tt.dnsName, got, tt.want)
			}
		})
	}
}
