package dnsforward

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghslog"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

type upstreamReloadState struct {
	mainUC    *proxy.UpstreamConfig
	privateUC *proxy.UpstreamConfig
	fallbacks *proxy.UpstreamConfig

	internalProxy *proxy.Proxy
	dnsProxy      *proxy.Proxy

	commonUpstreamConf *client.CommonUpstreamConfig
}

func (st *upstreamReloadState) close() (err error) {
	return errors.Join(
		closeUpstreamConfig(st.fallbacks),
		closeUpstreamConfig(st.privateUC),
		closeUpstreamConfig(st.mainUC),
	)
}

func closeUpstreamConfig(c *proxy.UpstreamConfig) (err error) {
	if c == nil {
		return nil
	}

	return c.Close()
}

func (s *Server) prepareUpstreamReloadState(ctx context.Context) (st *upstreamReloadState, err error) {
	if s.bootstrap == nil {
		return nil, errors.Error("bootstrap resolver is nil")
	} else if s.dnsProxy == nil {
		return nil, errors.Error("dns proxy is nil")
	}

	upstreams, err := s.conf.loadUpstreams(ctx, s.logger)
	if err != nil {
		return nil, fmt.Errorf("loading upstreams: %w", err)
	}

	managedUpstreams, err := s.loadManagedUpstreams(ctx, s.logger)
	if err != nil {
		return nil, fmt.Errorf("loading managed upstreams: %w", err)
	}

	upstreams = mergeUpstreams(upstreams, managedUpstreams)

	mainUC, err := newUpstreamConfig(ctx, s.logger, upstreams, defaultDNS, &upstream.Options{
		Logger:       aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeMain),
		Bootstrap:    s.bootstrap,
		Timeout:      s.conf.UpstreamTimeout,
		HTTPVersions: aghnet.UpstreamHTTPVersions(s.conf.UseHTTP3Upstreams),
		PreferIPv6:   s.conf.BootstrapPreferIPv6,
		RootCAs:      s.conf.TLSv12Roots,
		CipherSuites: s.conf.TLSCiphers,
	})
	if err != nil {
		return nil, fmt.Errorf("preparing upstream config: %w", err)
	}

	privateUC, err := s.prepareLocalResolvers(ctx)
	if err != nil {
		closeErr := closeUpstreamConfig(mainUC)

		return nil, errors.WithDeferred(err, closeErr)
	}

	internalProxy, err := s.newInternalProxy(mainUC, privateUC)
	if err != nil {
		closeErr := errors.Join(closeUpstreamConfig(privateUC), closeUpstreamConfig(mainUC))

		return nil, errors.WithDeferred(err, closeErr)
	}

	fallbacks, err := s.setupFallbackDNS()
	if err != nil {
		closeErr := errors.Join(closeUpstreamConfig(privateUC), closeUpstreamConfig(mainUC))

		return nil, errors.WithDeferred(err, closeErr)
	}

	primaryConf := s.dnsProxy.Config
	primaryConf.UpstreamConfig = mainUC
	primaryConf.PrivateRDNSUpstreamConfig = privateUC
	primaryConf.Fallbacks = fallbacks

	dnsProxy, err := proxy.New(&primaryConf)
	if err != nil {
		closeErr := errors.Join(
			closeUpstreamConfig(fallbacks),
			closeUpstreamConfig(privateUC),
			closeUpstreamConfig(mainUC),
		)

		return nil, errors.WithDeferred(err, closeErr)
	}

	commonUpstreamConf := &client.CommonUpstreamConfig{
		Bootstrap:               s.bootstrap,
		UpstreamTimeout:         s.conf.UpstreamTimeout,
		BootstrapPreferIPv6:     s.conf.BootstrapPreferIPv6,
		EDNSClientSubnetEnabled: s.conf.EDNSClientSubnet.Enabled,
		UseHTTP3Upstreams:       s.conf.UseHTTP3Upstreams,
	}

	return &upstreamReloadState{
		mainUC:             mainUC,
		privateUC:          privateUC,
		fallbacks:          fallbacks,
		internalProxy:      internalProxy,
		dnsProxy:           dnsProxy,
		commonUpstreamConf: commonUpstreamConf,
	}, nil
}

func (s *Server) newInternalProxy(
	mainUC, privateUC *proxy.UpstreamConfig,
) (internalProxy *proxy.Proxy, err error) {
	conf := &proxy.Config{
		Logger:                    s.baseLogger.With(slogutil.KeyPrefix, aghslog.PrefixDNSProxy),
		CacheEnabled:              true,
		CacheSizeBytes:            4096,
		PrivateRDNSUpstreamConfig: privateUC,
		UpstreamConfig:            mainUC,
		MaxGoroutines:             s.conf.MaxGoroutines,
		UseDNS64:                  s.conf.UseDNS64,
		DNS64Prefs:                s.conf.DNS64Prefixes,
		UsePrivateRDNS:            s.conf.UsePrivateRDNS,
		PrivateSubnets:            s.privateNets,
		MessageConstructor:        s,
	}

	err = setProxyUpstreamMode(conf, s.conf.UpstreamMode, time.Duration(s.conf.FastestTimeout))
	if err != nil {
		return nil, fmt.Errorf("invalid upstream mode: %w", err)
	}

	return proxy.New(conf)
}

func (s *Server) reloadUpstreamsStartWithRetry(
	ctx context.Context,
	l *slog.Logger,
	attempts int,
) (err error) {
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * 100 * time.Millisecond)
		}

		err = s.startLocked(ctx)
		if err == nil {
			return nil
		}

		l.ErrorContext(
			ctx,
			"restarting dns server after upstream reload",
			"attempt", i+1,
			"attempts", attempts,
			slogutil.KeyError, err,
		)
	}

	return err
}
