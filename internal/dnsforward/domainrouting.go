package dnsforward

import (
	"strings"

	"github.com/AdguardTeam/dnsproxy/proxy"
)

// hasDomainSpecificUpstream returns true if resolving fqdn would use a
// domain-specific upstream from uc instead of the default upstream set.  The
// matching rules mirror [proxy.UpstreamConfig] domain lookup behavior.
func hasDomainSpecificUpstream(uc *proxy.UpstreamConfig, fqdn string) (ok bool) {
	if uc == nil || len(uc.DomainReservedUpstreams) == 0 {
		return false
	}

	fqdn = strings.ToLower(fqdn)
	if uc.SubdomainExclusions != nil && uc.SubdomainExclusions.Has(fqdn) {
		if len(uc.SpecifiedDomainUpstreams[fqdn]) > 0 {
			return true
		}

		// Match dnsproxy's lookupSubdomainExclusion behavior and only inspect
		// the immediate parent domain for wildcard exclusions.
		_, parent, _ := strings.Cut(fqdn, ".")

		return len(uc.DomainReservedUpstreams[parent]) > 0
	}

	for name := fqdn; name != ""; {
		ups, found := uc.DomainReservedUpstreams[name]
		if found {
			// An empty upstream list means the domain is excluded from
			// domain-specific routing and should use the default set.
			return len(ups) > 0
		}

		_, name, _ = strings.Cut(name, ".")
	}

	return false
}
