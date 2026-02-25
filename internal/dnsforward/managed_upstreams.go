package dnsforward

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/stringutil"
)

func (s *Server) loadManagedUpstreams(
	ctx context.Context,
	l *slog.Logger,
) (upstreams []string, err error) {
	if s.dnsFilter == nil {
		return nil, nil
	}

	var c filtering.Config
	s.dnsFilter.WriteDiskConfig(&c)

	for _, file := range c.UpstreamDNSFiles {
		if !file.Enabled {
			continue
		}

		path := file.Path(c.DataDir)
		var data []byte
		data, err = os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return nil, fmt.Errorf("reading upstream dns file %s: %w", path, err)
		}

		fileUpstreams := stringutil.SplitTrimmed(string(data), "\n")
		upstreams = append(upstreams, stringutil.FilterOut(fileUpstreams, aghnet.IsCommentOrEmpty)...)
	}

	if len(upstreams) > 0 {
		l.DebugContext(ctx, "got upstreams from managed files", "number", len(upstreams))
	}

	return upstreams, nil
}

// mergeUpstreams merges multiple upstream DNS lists and removes duplicates.
// It preserves the order of upstreams, keeping the first occurrence of each
// unique upstream server.
func mergeUpstreams(lists ...[]string) []string {
	seen := container.NewMapSet[string]()
	var merged []string

	for _, list := range lists {
		for _, upstream := range list {
			if !seen.Has(upstream) {
				seen.Add(upstream)
				merged = append(merged, upstream)
			}
		}
	}

	return merged
}
