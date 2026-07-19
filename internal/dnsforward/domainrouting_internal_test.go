package dnsforward

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasDomainSpecificUpstream(t *testing.T) {
	t.Parallel()

	upsConf, err := proxy.ParseUpstreamsConfig(
		[]string{
			"[/lan/]1.1.1.1",
			"[/*.host.com/]2.2.2.2",
			"[/www.host.com/]3.3.3.3",
			"[/maps.host.com/]#",
			"8.8.8.8",
		},
		&upstream.Options{Logger: slogutil.NewDiscardLogger()},
	)
	require.NoError(t, err)

	testCases := []struct {
		name string
		fqdn string
		want bool
	}{{
		name: "exact_local",
		fqdn: "pc.lan.",
		want: true,
	}, {
		name: "local_suffix",
		fqdn: "lan.",
		want: true,
	}, {
		name: "wildcard_subdomain",
		fqdn: "a.host.com.",
		want: true,
	}, {
		name: "more_specific",
		fqdn: "www.host.com.",
		want: true,
	}, {
		name: "excluded_to_default",
		fqdn: "maps.host.com.",
		want: false,
	}, {
		name: "unrelated",
		fqdn: "example.org.",
		want: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, hasDomainSpecificUpstream(upsConf, tc.fqdn))
		})
	}

	t.Run("nil_config", func(t *testing.T) {
		t.Parallel()

		assert.False(t, hasDomainSpecificUpstream(nil, "pc.lan."))
	})
}
