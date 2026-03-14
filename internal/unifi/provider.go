package unifi

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/kashalls/external-dns-unifi-webhook/cmd/webhook/init/log"
	"github.com/kashalls/external-dns-unifi-webhook/pkg/metrics"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// UnifiProvider type for interfacing with UniFi.
//
//nolint:revive // UnifiProvider is the correct name for this provider, renaming would be a breaking change
type UnifiProvider struct {
	provider.BaseProvider

	client       *httpClient
	domainFilter endpoint.DomainFilter
}

const (
	providerSpecificUniFiDNS         = "unifi-dns"
	providerSpecificUniFiPortForward = "unifi-port-forward"
	defaultPortForwardProtocol       = "tcp"
	defaultPortForwardSrc            = "any"
	defaultPortForwardDstIP          = "any"
	defaultPortForwardInterface      = "wan"
)

type portForwardMapping struct {
	srcPort string
	dstPort string
}

// NewUnifiProvider initializes a new DNSProvider.
//
//nolint:ireturn // Must return provider.Provider interface as required by external-dns API
func NewUnifiProvider(domainFilter endpoint.DomainFilter, config *Config) (provider.Provider, error) {
	c, err := newUnifiClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the unifi client")
	}

	p := &UnifiProvider{
		client:       c,
		domainFilter: domainFilter,
	}

	return p, nil
}

// Records returns the list of records in the DNS provider.
func (p *UnifiProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	m := metrics.Get()

	records, err := p.client.GetEndpoints(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch DNS records")
	}

	// Count records by type for metrics
	recordsByType := make(map[string]int)
	for _, r := range records {
		if provider.SupportedRecordType(r.RecordType) {
			recordsByType[r.RecordType]++
		}
	}

	// Update metrics for each record type
	for recordType, count := range recordsByType {
		m.UpdateRecordsByType(recordType, count)
	}

	groups := make(map[string][]DNSRecord)
	for _, r := range records {
		if provider.SupportedRecordType(r.RecordType) {
			groupKey := r.Key + r.RecordType
			groups[groupKey] = append(groups[groupKey], r)
		}
	}

	var endpoints []*endpoint.Endpoint
	for _, records := range groups {
		if len(records) == 0 {
			continue
		}

		targets := make([]string, len(records))
		for i, record := range records {
			targets[i] = record.Value
		}

		if ep := endpoint.NewEndpointWithTTL(
			records[0].Key, records[0].RecordType, records[0].TTL, targets...,
		); ep != nil {
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}

// ApplyChanges applies a given set of changes in the DNS provider.
func (p *UnifiProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	m := metrics.Get()

	requiresPortForward := hasAnyPortForwardIntent(changes)
	portForwardRulesByName := make(map[string]PortForwardRule)
	if requiresPortForward {
		rules, err := p.client.GetPortForwardRules(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to list existing port-forward rules")
		}

		for _, rule := range rules {
			portForwardRulesByName[rule.Name] = rule
		}
	}

	existingRecords, err := p.Records(ctx)
	if err != nil {
		log.Error("failed to get records while applying", "error", err)

		return errors.Wrap(err, "failed to get existing records before applying changes")
	}

	// Record batch sizes
	m.BatchSize.WithLabelValues(metrics.ProviderName, "create").Observe(float64(len(changes.Create)))
	m.BatchSize.WithLabelValues(metrics.ProviderName, "update").Observe(float64(len(changes.UpdateNew)))
	m.BatchSize.WithLabelValues(metrics.ProviderName, "delete").Observe(float64(len(changes.Delete)))

	// Process deletions and updates (delete old)
	for _, endpoint := range append(changes.UpdateOld, changes.Delete...) {
		err := p.client.DeleteEndpoint(ctx, endpoint)
		if err != nil {
			log.Error("failed to delete endpoint", "data", endpoint, "error", err)

			return errors.Wrapf(err, "failed to delete endpoint %s (%s)", endpoint.DNSName, endpoint.RecordType)
		}
		m.RecordChange("delete", endpoint.RecordType)

		if requiresPortForward {
			err = p.reconcilePortForwardDelete(ctx, endpoint, portForwardRulesByName)
			if err != nil {
				return errors.Wrapf(err, "failed to reconcile port-forward delete for endpoint %s", endpoint.DNSName)
			}
		}
	}

	// Process creates and updates (create new)
	for _, endpoint := range append(changes.Create, changes.UpdateNew...) {
		operation := "create"
		// Check for CNAME conflicts
		if endpoint.RecordType == recordTypeCNAME {
			for _, record := range existingRecords {
				if record.RecordType != recordTypeCNAME {
					continue
				}

				if record.DNSName != endpoint.DNSName {
					continue
				}

				m.CNAMEConflictsTotal.WithLabelValues(metrics.ProviderName).Inc()
				err := p.client.DeleteEndpoint(ctx, record)
				if err != nil {
					log.Error("failed to delete conflicting CNAME", "data", record, "error", err)

					return errors.Wrapf(err, "failed to delete conflicting CNAME %s", record.DNSName)
				}
			}
		}
		_, err := p.client.CreateEndpoint(ctx, endpoint)
		if err != nil {
			log.Error("failed to create endpoint", "data", endpoint, "error", err)

			return errors.Wrapf(err, "failed to create endpoint %s (%s)", endpoint.DNSName, endpoint.RecordType)
		}
		m.RecordChange(operation, endpoint.RecordType)

		if requiresPortForward {
			err = p.reconcilePortForwardUpsert(ctx, endpoint, portForwardRulesByName)
			if err != nil {
				return errors.Wrapf(err, "failed to reconcile port-forward rule for endpoint %s", endpoint.DNSName)
			}
		}
	}

	return nil
}

// AdjustEndpoints filters the webhook payload to UniFi-local intent only.
// Endpoints are reconciled for UniFi when either:
// - unifi-dns=true
// - unifi-port-forward=<src>:<dst> is set
func (p *UnifiProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	adjusted := make([]*endpoint.Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		if ep == nil {
			continue
		}

		if endpointHasUniFiIntent(ep) {
			adjusted = append(adjusted, ep)
		}
	}

	return adjusted, nil
}

// GetDomainFilter returns the domain filter for the provider.
//
//nolint:ireturn // Must return endpoint.DomainFilterInterface as required by external-dns API
func (p *UnifiProvider) GetDomainFilter() endpoint.DomainFilterInterface {
	return &p.domainFilter
}

func hasAnyPortForwardIntent(changes *plan.Changes) bool {
	all := make([]*endpoint.Endpoint, 0, len(changes.Create)+len(changes.UpdateOld)+len(changes.UpdateNew)+len(changes.Delete))
	all = append(all, changes.Create...)
	all = append(all, changes.UpdateOld...)
	all = append(all, changes.UpdateNew...)
	all = append(all, changes.Delete...)

	for _, ep := range all {
		if ep == nil {
			continue
		}

		if _, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward); ok {
			return true
		}
	}

	return false
}

func endpointHasUniFiIntent(ep *endpoint.Endpoint) bool {
	enabled, ok := ep.GetBoolProviderSpecificProperty(providerSpecificUniFiDNS)
	if ok && enabled {
		return true
	}

	if _, hasPortForward := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward); hasPortForward {
		return true
	}

	return false
}

func parsePortForwardMapping(value string) (portForwardMapping, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return portForwardMapping{}, errors.Newf("invalid %s value %q: expected <src>:<dst>", providerSpecificUniFiPortForward, value)
	}

	srcPort := strings.TrimSpace(parts[0])
	dstPort := strings.TrimSpace(parts[1])

	if err := validatePort(srcPort); err != nil {
		return portForwardMapping{}, errors.Wrap(err, "invalid source port")
	}

	if err := validatePort(dstPort); err != nil {
		return portForwardMapping{}, errors.Wrap(err, "invalid destination port")
	}

	return portForwardMapping{srcPort: srcPort, dstPort: dstPort}, nil
}

func validatePort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil {
		return errors.Wrapf(err, "port %q is not numeric", port)
	}

	if value < 1 || value > 65535 {
		return errors.Newf("port %q is out of range (1-65535)", port)
	}

	return nil
}

func normalizedRuleName(dnsName string, mapping portForwardMapping) string {
	host := strings.TrimSuffix(strings.ToLower(dnsName), ".")
	host = strings.ReplaceAll(host, ".", "-")
	host = strings.ReplaceAll(host, "_", "-")

	return fmt.Sprintf("extdns-%s-%s-%s", host, mapping.srcPort, mapping.dstPort)
}

func desiredPortForwardRule(ep *endpoint.Endpoint, mapping portForwardMapping) (PortForwardRule, error) {
	if len(ep.Targets) == 0 {
		return PortForwardRule{}, errors.New("port-forward endpoint must include at least one target")
	}

	target := strings.TrimSpace(ep.Targets[0])
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		return PortForwardRule{}, errors.Newf("port-forward target must be an IPv4 address, got %q", target)
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

func (p *UnifiProvider) reconcilePortForwardDelete(
	ctx context.Context,
	ep *endpoint.Endpoint,
	rulesByName map[string]PortForwardRule,
) error {
	value, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward)
	if !ok {
		return nil
	}

	mapping, err := parsePortForwardMapping(value)
	if err != nil {
		return err
	}

	ruleName := normalizedRuleName(ep.DNSName, mapping)
	existingRule, found := rulesByName[ruleName]
	if !found {
		return nil
	}

	err = p.client.DeletePortForwardRule(ctx, existingRule.ID)
	if err != nil {
		return err
	}

	delete(rulesByName, ruleName)
	log.Info("deleted UniFi port-forward rule", "rule", ruleName)

	return nil
}

func (p *UnifiProvider) reconcilePortForwardUpsert(
	ctx context.Context,
	ep *endpoint.Endpoint,
	rulesByName map[string]PortForwardRule,
) error {
	value, ok := ep.GetProviderSpecificProperty(providerSpecificUniFiPortForward)
	if !ok {
		return nil
	}

	mapping, err := parsePortForwardMapping(value)
	if err != nil {
		return err
	}

	desiredRule, err := desiredPortForwardRule(ep, mapping)
	if err != nil {
		return err
	}

	existingRule, found := rulesByName[desiredRule.Name]
	if !found {
		createdRule, err := p.client.CreatePortForwardRule(ctx, desiredRule)
		if err != nil {
			return err
		}

		rulesByName[desiredRule.Name] = *createdRule
		log.Info("created UniFi port-forward rule", "rule", desiredRule.Name)

		return nil
	}

	if samePortForwardRule(existingRule, desiredRule) {
		return nil
	}

	err = p.client.UpdatePortForwardRule(ctx, existingRule.ID, desiredRule)
	if err != nil {
		return err
	}

	desiredRule.ID = existingRule.ID
	rulesByName[desiredRule.Name] = desiredRule
	log.Info("updated UniFi port-forward rule", "rule", desiredRule.Name)

	return nil
}
