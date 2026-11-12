package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/home-operations/external-dns-unifi-webhook/internal/metrics"
	"sigs.k8s.io/external-dns/endpoint"
	extdnshttp "sigs.k8s.io/external-dns/pkg/http"
	"sigs.k8s.io/external-dns/plan"
)

// Provider-specific property names carried on an endpoint. ExternalDNS copies
// the matching annotations into providerSpecific entries, so an HTTPRoute can
// opt in with:
//
//	external-dns.alpha.kubernetes.io/webhook-unifi-dns: "true"
//	external-dns.alpha.kubernetes.io/webhook-unifi-port-forward: "443:8443"
const (
	providerSpecificUniFiDNS         = "unifi-dns"
	providerSpecificUniFiPortForward = "unifi-port-forward"
)

// Defaults applied to a managed port-forward rule. The UniFi UI writes the same
// values for a rule created through the web UI for "any" source.
const (
	defaultPortForwardProtocol  = "tcp"
	defaultPortForwardSrc       = "any"
	defaultPortForwardDstIP     = "any"
	defaultPortForwardInterface = "wan"
)

// The port-forward REST endpoints live under /proxy/network/api/s/... rather
// than under the /v2/api/... static-DNS tree: the v2 tree only carries DNS.
const (
	pathPortForwardRules = "%s/proxy/network/api/s/%s/rest/portforward"
	pathPortForwardRule  = "%s/proxy/network/api/s/%s/rest/portforward/%s"
)

// PortForwardRule is a UniFi port-forward (destination NAT) rule.
//
// Only the fields this provider writes are modelled; the controller returns
// more and ignores what is absent on an update.
//
//nolint:tagliatelle // UniFi API field names cannot be changed
type PortForwardRule struct {
	ID            string `json:"_id,omitempty"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Proto         string `json:"proto"`
	Src           string `json:"src"`
	DestinationIP string `json:"destination_ip"`
	DstPort       string `json:"dst_port"`
	Fwd           string `json:"fwd"`
	FwdPort       string `json:"fwd_port"`
	PfwdInterface string `json:"pfwd_interface"`
	Log           bool   `json:"log"`
}

// portForwardEnvelope is the REST envelope the port-forward endpoints use:
// the payload is nested under "data" rather than returned bare.
//
//nolint:tagliatelle // UniFi API field names cannot be changed
type portForwardEnvelope struct {
	Data []PortForwardRule `json:"data"`
}

// portForwardMapping is the parsed <src>:<dst> annotation value.
type portForwardMapping struct {
	srcPort string
	dstPort string
}

// GetPortForwardRules lists every port-forward rule on the site.
func (c *httpClient) GetPortForwardRules(ctx context.Context) (rules []PortForwardRule, err error) {
	start := time.Now()
	var bodyRead int
	defer func() {
		metrics.Get().RecordUniFiAPICall("get_port_forward_rules", time.Since(start), bodyRead, err)
	}()

	var envelope portForwardEnvelope
	bodyRead, err = c.getJSON(
		ctx,
		formatURL(pathPortForwardRules, c.cfg.baseURL(), c.siteName),
		"port-forward rules",
		&envelope,
	)
	if err != nil {
		return nil, fmt.Errorf("fetching port-forward rules from UniFi: %w", err)
	}

	return envelope.Data, nil
}

// CreatePortForwardRule creates a rule and returns what the controller stored.
func (c *httpClient) CreatePortForwardRule(ctx context.Context, rule PortForwardRule) (*PortForwardRule, error) {
	return c.writePortForwardRule(ctx, http.MethodPost,
		formatURL(pathPortForwardRules, c.cfg.baseURL(), c.siteName), rule, "create_port_forward_rule")
}

// UpdatePortForwardRule replaces the rule with the given ID.
func (c *httpClient) UpdatePortForwardRule(ctx context.Context, id string, rule PortForwardRule) (*PortForwardRule, error) {
	rule.ID = id

	return c.writePortForwardRule(ctx, http.MethodPut,
		formatURL(pathPortForwardRule, c.cfg.baseURL(), c.siteName, id), rule, "update_port_forward_rule")
}

// DeletePortForwardRule removes a rule by ID. A 404 is treated as success for
// the same reason DeleteRecord does: the rule is already gone, which is the
// outcome the caller wants.
func (c *httpClient) DeletePortForwardRule(ctx context.Context, id string) (err error) {
	start := time.Now()
	defer func() {
		metrics.Get().RecordUniFiAPICall("delete_port_forward_rule", time.Since(start), 0, err)
	}()

	u := formatURL(pathPortForwardRule, c.cfg.baseURL(), c.siteName, id)
	resp, derr := c.doRequest(ctx, http.MethodDelete, u, nil)
	if derr != nil {
		if apiErr, ok := errors.AsType[*APIError](derr); ok && apiErr.StatusCode == http.StatusNotFound {
			slog.Debug("port-forward rule already deleted", "id", id)

			return nil
		}

		return fmt.Errorf("deleting port-forward rule %s: %w", id, derr)
	}
	extdnshttp.DrainAndClose(resp.Body)
	slog.Debug("removed port-forward rule", "id", id)

	return nil
}

func (c *httpClient) writePortForwardRule(
	ctx context.Context, method, requestURL string, rule PortForwardRule, operation string,
) (created *PortForwardRule, err error) {
	start := time.Now()
	var bodyRead int
	defer func() {
		metrics.Get().RecordUniFiAPICall(operation, time.Since(start), bodyRead, err)
	}()

	body, err := json.Marshal(rule)
	if err != nil {
		return nil, NewDataError("marshal", "port-forward rule", err)
	}

	resp, err := c.doRequest(ctx, method, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", strings.ToLower(method), "port-forward rule", err)
	}
	defer extdnshttp.DrainAndClose(resp.Body)

	var envelope portForwardEnvelope
	bodyRead, err = decodeJSON(resp, "port-forward rule", &envelope)
	if err != nil {
		return nil, err
	}
	if len(envelope.Data) == 0 {
		return nil, NewDataError("convert", "port-forward rule", errors.New("controller returned no rule"))
	}

	return &envelope.Data[0], nil
}

// hasAnyPortForwardIntent reports whether any endpoint in the change set asked
// for a port-forward, so the rule list is only fetched when it is needed.
func hasAnyPortForwardIntent(changes *plan.Changes) bool {
	for _, ep := range changeEndpoints(changes) {
		if _, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward); ok {
			return true
		}
	}

	return false
}

// changeEndpoints flattens the four endpoint lists of a plan into one slice.
func changeEndpoints(changes *plan.Changes) []*endpoint.Endpoint {
	all := make([]*endpoint.Endpoint, 0,
		len(changes.Create)+len(changes.UpdateOld)+len(changes.UpdateNew)+len(changes.Delete))
	all = append(all, changes.Create...)
	all = append(all, changes.UpdateOld...)
	all = append(all, changes.UpdateNew...)
	all = append(all, changes.Delete...)

	return all
}

// endpointHasUniFiIntent reports whether external-dns should hand this endpoint
// to the UniFi provider at all.
func endpointHasUniFiIntent(ep *endpoint.Endpoint) bool {
	if raw, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiDNS); ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true", "1", "yes", "on":
			return true
		}
	}

	_, hasPortForward := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward)

	return hasPortForward
}

func parsePortForwardMapping(value string) (portForwardMapping, error) {
	srcPort, dstPort, found := strings.Cut(value, ":")
	if !found {
		return portForwardMapping{}, fmt.Errorf(
			"invalid %s value %q: expected <src>:<dst>", providerSpecificUniFiPortForward, value)
	}

	mapping := portForwardMapping{
		srcPort: strings.TrimSpace(srcPort),
		dstPort: strings.TrimSpace(dstPort),
	}
	if err := validatePort(mapping.srcPort); err != nil {
		return portForwardMapping{}, fmt.Errorf("invalid source port: %w", err)
	}
	if err := validatePort(mapping.dstPort); err != nil {
		return portForwardMapping{}, fmt.Errorf("invalid destination port: %w", err)
	}

	return mapping, nil
}

func validatePort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port %q is not numeric: %w", port, err)
	}
	if value < 1 || value > 65535 {
		return fmt.Errorf("port %q is out of range (1-65535)", port)
	}

	return nil
}

// normalizedRuleName derives a stable rule name from the hostname and mapping,
// so a rule can be found again across reconciles without keeping local state.
func normalizedRuleName(dnsName string, mapping portForwardMapping) string {
	host := strings.TrimSuffix(strings.ToLower(dnsName), ".")
	host = strings.NewReplacer(".", "-", "_", "-").Replace(host)

	return fmt.Sprintf("extdns-%s-%s-%s", host, mapping.srcPort, mapping.dstPort)
}

func desiredPortForwardRule(ep *endpoint.Endpoint, mapping portForwardMapping) (PortForwardRule, error) {
	if len(ep.Targets) == 0 {
		return PortForwardRule{}, errors.New("port-forward endpoint must include at least one target")
	}

	target := strings.TrimSpace(ep.Targets[0])
	if ip := net.ParseIP(target); ip == nil || ip.To4() == nil {
		return PortForwardRule{}, fmt.Errorf("port-forward target must be an IPv4 address, got %q", target)
	}

	return PortForwardRule{
		Name:          normalizedRuleName(ep.DNSName, mapping),
		Enabled:       true,
		Proto:         defaultPortForwardProtocol,
		Src:           defaultPortForwardSrc,
		DestinationIP: defaultPortForwardDstIP,
		DstPort:       mapping.srcPort,
		Fwd:           target,
		FwdPort:       mapping.dstPort,
		PfwdInterface: defaultPortForwardInterface,
		Log:           false,
	}, nil
}

func samePortForwardRule(a, b PortForwardRule) bool {
	return a.Name == b.Name &&
		a.Enabled == b.Enabled &&
		a.Proto == b.Proto &&
		a.Src == b.Src &&
		a.DestinationIP == b.DestinationIP &&
		a.DstPort == b.DstPort &&
		a.Fwd == b.Fwd &&
		a.FwdPort == b.FwdPort &&
		a.PfwdInterface == b.PfwdInterface &&
		a.Log == b.Log
}

// reconcilePortForwards brings UniFi port-forward rules in line with the
// endpoints that carry a unifi-port-forward property. Deletes run before
// creates, matching the ordering external-dns already applies to DNS records.
func (p *UnifiProvider) reconcilePortForwards(ctx context.Context, changes *plan.Changes) error {
	if !hasAnyPortForwardIntent(changes) {
		return nil
	}

	rules, err := p.client.GetPortForwardRules(ctx)
	if err != nil {
		return fmt.Errorf("listing port-forward rules: %w", err)
	}

	byName := make(map[string]PortForwardRule, len(rules))
	for _, rule := range rules {
		byName[rule.Name] = rule
	}

	for _, ep := range slices.Concat(changes.UpdateOld, changes.Delete) {
		if err := p.deletePortForwardFor(ctx, ep, byName); err != nil {
			return err
		}
	}

	for _, ep := range slices.Concat(changes.Create, changes.UpdateNew) {
		if err := p.upsertPortForwardFor(ctx, ep, byName); err != nil {
			return err
		}
	}

	return nil
}

func (p *UnifiProvider) deletePortForwardFor(
	ctx context.Context, ep *endpoint.Endpoint, byName map[string]PortForwardRule,
) error {
	value, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward)
	if !ok {
		return nil
	}

	mapping, err := parsePortForwardMapping(value)
	if err != nil {
		return fmt.Errorf("endpoint %s: %w", ep.DNSName, err)
	}

	ruleName := normalizedRuleName(ep.DNSName, mapping)
	existing, found := byName[ruleName]
	if !found {
		return nil
	}

	if err := p.client.DeletePortForwardRule(ctx, existing.ID); err != nil {
		return fmt.Errorf("deleting port-forward rule %s: %w", ruleName, err)
	}

	delete(byName, ruleName)
	slog.Info("deleted UniFi port-forward rule", "rule", ruleName)

	return nil
}

func (p *UnifiProvider) upsertPortForwardFor(
	ctx context.Context, ep *endpoint.Endpoint, byName map[string]PortForwardRule,
) error {
	value, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward)
	if !ok {
		return nil
	}

	mapping, err := parsePortForwardMapping(value)
	if err != nil {
		return fmt.Errorf("endpoint %s: %w", ep.DNSName, err)
	}

	desired, err := desiredPortForwardRule(ep, mapping)
	if err != nil {
		return fmt.Errorf("endpoint %s: %w", ep.DNSName, err)
	}

	existing, found := byName[desired.Name]
	if !found {
		created, err := p.client.CreatePortForwardRule(ctx, desired)
		if err != nil {
			return fmt.Errorf("creating port-forward rule %s: %w", desired.Name, err)
		}

		byName[desired.Name] = *created
		slog.Info("created UniFi port-forward rule", "rule", desired.Name)

		return nil
	}

	if samePortForwardRule(existing, desired) {
		return nil
	}

	updated, err := p.client.UpdatePortForwardRule(ctx, existing.ID, desired)
	if err != nil {
		return fmt.Errorf("updating port-forward rule %s: %w", desired.Name, err)
	}

	byName[desired.Name] = *updated
	slog.Info("updated UniFi port-forward rule", "rule", desired.Name)

	return nil
}
