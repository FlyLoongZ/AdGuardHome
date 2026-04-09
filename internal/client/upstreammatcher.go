package client

import (
	"strings"

	"github.com/AdguardTeam/dnsproxy/proxy"
)

// newSpecificUpstreamMatcher returns a matcher that reports whether fqdn would
// use a domain-specific upstream instead of the default upstream set.
func newSpecificUpstreamMatcher(uc *proxy.UpstreamConfig) (match func(fqdn string) (ok bool)) {
	if uc == nil {
		return nil
	}

	return func(fqdn string) (ok bool) {
		return hasDomainSpecificUpstream(uc, fqdn)
	}
}

// hasDomainSpecificUpstream returns true if resolving fqdn would use a
// domain-specific upstream from uc instead of the default upstream set.
func hasDomainSpecificUpstream(uc *proxy.UpstreamConfig, fqdn string) (ok bool) {
	if uc == nil || len(uc.DomainReservedUpstreams) == 0 {
		return false
	}

	fqdn = strings.ToLower(fqdn)
	if uc.SubdomainExclusions != nil && uc.SubdomainExclusions.Has(fqdn) {
		if len(uc.SpecifiedDomainUpstreams[fqdn]) > 0 {
			return true
		}

		_, parent, _ := strings.Cut(fqdn, ".")

		return len(uc.DomainReservedUpstreams[parent]) > 0
	}

	for name := fqdn; name != ""; {
		ups, found := uc.DomainReservedUpstreams[name]
		if found {
			return len(ups) > 0
		}

		_, name, _ = strings.Cut(name, ".")
	}

	return false
}
