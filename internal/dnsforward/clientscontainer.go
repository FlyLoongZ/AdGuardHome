package dnsforward

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
)

// ClientsContainer provides information about preconfigured DNS clients.
type ClientsContainer interface {
	// CustomUpstreamConfig returns the custom client upstream configuration, if
	// any.  It prioritizes ClientID over client IP address to identify the
	// client.
	CustomUpstreamConfig(clientID string, cliAddr netip.Addr) (conf *proxy.CustomUpstreamConfig)

	// HasCustomDomainSpecificUpstream returns true if the identified client has a
	// domain-specific custom upstream for fqdn.
	HasCustomDomainSpecificUpstream(clientID string, cliAddr netip.Addr, fqdn string) (ok bool)

	// UpdateCommonUpstreamConfig updates the common upstream configuration.
	UpdateCommonUpstreamConfig(conf *client.CommonUpstreamConfig)

	// ClearUpstreamCache clears the upstream cache for each stored custom
	// client upstream configuration.
	ClearUpstreamCache()
}

// EmptyClientsContainer is an [ClientsContainer] implementation that does nothing.
type EmptyClientsContainer struct{}

// type check
var _ ClientsContainer = EmptyClientsContainer{}

// CustomUpstreamConfig implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) CustomUpstreamConfig(
	clientID string,
	cliAddr netip.Addr,
) (conf *proxy.CustomUpstreamConfig) {
	return nil
}

// HasCustomDomainSpecificUpstream implements the [ClientsContainer] interface
// for EmptyClientsContainer.
func (EmptyClientsContainer) HasCustomDomainSpecificUpstream(
	clientID string,
	cliAddr netip.Addr,
	fqdn string,
) (ok bool) {
	return false
}

// UpdateCommonUpstreamConfig implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) UpdateCommonUpstreamConfig(conf *client.CommonUpstreamConfig) {}

// ClearUpstreamCache implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) ClearUpstreamCache() {}
