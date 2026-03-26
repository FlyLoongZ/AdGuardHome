package dnsforward

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/stringutil"
)

type upstreamSourceJSON struct {
	ID          uint64 `json:"id"`
	URL         string `json:"url"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	RulesCount  uint64 `json:"rules_count"`
	LastUpdated string `json:"last_updated,omitempty"`
}

func sourceToJSON(src UpstreamDNSSourceYAML) (sj upstreamSourceJSON) {
	sj = upstreamSourceJSON{
		ID:      src.ID,
		URL:     src.URL,
		Name:    src.Name,
		Enabled: src.Enabled,
	}

	if src.RulesCount > 0 {
		sj.RulesCount = uint64(src.RulesCount)
	}

	if !src.LastUpdated.IsZero() {
		sj.LastUpdated = src.LastUpdated.Format(time.RFC3339)
	}

	return sj
}

func sourcesToJSON(sources []UpstreamDNSSourceYAML) (res []upstreamSourceJSON) {
	res = make([]upstreamSourceJSON, 0, len(sources))
	for _, src := range sources {
		res = append(res, sourceToJSON(src))
	}

	return res
}

func sourceFromJSON(src upstreamSourceJSON) (res UpstreamDNSSourceYAML) {
	res = UpstreamDNSSourceYAML{
		Enabled: src.Enabled,
		URL:     src.URL,
		Name:    src.Name,
		UpstreamDNSSource: UpstreamDNSSource{
			ID: src.ID,
		},
	}

	if src.RulesCount > 0 {
		res.RulesCount = int(src.RulesCount)
	}

	if src.LastUpdated != "" {
		if t, err := time.Parse(time.RFC3339, src.LastUpdated); err == nil {
			res.LastUpdated = t
		}
	}

	return res
}

func sourcesFromJSON(sources []upstreamSourceJSON) (res []UpstreamDNSSourceYAML) {
	res = make([]UpstreamDNSSourceYAML, 0, len(sources))
	for _, src := range sources {
		res = append(res, sourceFromJSON(src))
	}

	return res
}

func ptrSourceSlice(src *[]upstreamSourceJSON) (res *[]UpstreamDNSSourceYAML) {
	if src == nil {
		return nil
	}

	parsed := sourcesFromJSON(*src)

	return &parsed
}

type upstreamSourceAddJSON struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type upstreamSourceSetDataJSON struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled *bool  `json:"enabled"`
}

type upstreamSourceSetReq struct {
	Data *upstreamSourceSetDataJSON `json:"data"`
	URL  string                     `json:"url"`
}

type upstreamSourceStatusResp struct {
	Sources []upstreamSourceJSON `json:"sources"`
}

func (s *Server) handleUpstreamSourcesStatus(w http.ResponseWriter, r *http.Request) {
	s.serverLock.RLock()
	sources := s.upstreamSources.all()
	s.serverLock.RUnlock()

	aghhttp.WriteJSONResponseOK(r.Context(), s.logger, w, r, upstreamSourceStatusResp{
		Sources: sourcesToJSON(sources),
	})
}

func (s *Server) handleUpstreamSourcesAddURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &upstreamSourceAddJSON{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	stage, err := s.upstreamSources.stageAdd(ctx, UpstreamDNSSourceYAML{Enabled: true, URL: req.URL, Name: req.Name})
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if stage.requiresRestart {
		reErr := s.reconfigureWithUpstreamSources(ctx, stage.staged, stage.prepared)
		if reErr != nil {
			s.upstreamSources.cleanupPrepared(stage.prepared)
			aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

			return
		}
	}

	err = s.upstreamSources.applyStaged(stage)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)

	aghhttp.OK(ctx, s.logger, w)
}

func (s *Server) handleUpstreamSourcesRemoveURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &upstreamSourceAddJSON{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	stage, err := s.upstreamSources.stageRemove(req.URL)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if stage.requiresRestart {
		if reErr := s.reconfigureWithUpstreamSources(ctx, stage.staged, nil); reErr != nil {
			aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

			return
		}
	}

	err = s.upstreamSources.applyStaged(stage)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)

	aghhttp.OK(ctx, s.logger, w)
}

func (s *Server) handleUpstreamSourcesSetURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &upstreamSourceSetReq{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	if req.Data == nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "data is absent")

		return
	}

	enabled := true
	if req.Data.Enabled != nil {
		enabled = *req.Data.Enabled
	}

	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	stage, err := s.upstreamSources.stageSet(ctx, req.URL, UpstreamDNSSourceYAML{
		Name:    req.Data.Name,
		URL:     req.Data.URL,
		Enabled: enabled,
	})
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if stage.staged == nil {
		aghhttp.OK(ctx, s.logger, w)

		return
	}

	if stage.requiresRestart {
		if reErr := s.reconfigureWithUpstreamSources(ctx, stage.staged, stage.prepared); reErr != nil {
			s.upstreamSources.cleanupPrepared(stage.prepared)
			aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

			return
		}
	}

	err = s.upstreamSources.applyStaged(stage)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)

	aghhttp.OK(ctx, s.logger, w)
}

func (s *Server) handleUpstreamSourcesRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	stage, err := s.upstreamSources.stageRefresh(ctx, true)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	for _, warn := range stage.warnings {
		s.logger.WarnContext(ctx, "refreshing upstream source", slogutil.KeyError, warn)
	}

	if stage.requiresRestart {
		if reErr := s.reconfigureWithUpstreamSources(ctx, stage.staged, stage.prepared); reErr != nil {
			s.upstreamSources.cleanupPrepared(stage.prepared)
			aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

			return
		}
	}

	err = s.upstreamSources.applyStaged(stage)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)

	aghhttp.WriteJSONResponseOK(ctx, s.logger, w, r, struct {
		Updated int `json:"updated"`
	}{Updated: stage.updated})
}

func (s *Server) reconfigureWithUpstreamSources(
	ctx context.Context,
	sources []UpstreamDNSSourceYAML,
	prepared []sourcePrepared,
) (err error) {
	s.serverLock.RLock()
	staged := s.conf
	s.serverLock.RUnlock()

	realDataDir := staged.DataDir
	staged.UpstreamDNSSources = slices.Clone(sources)

	cacheDir, err := os.MkdirTemp(s.conf.DataDir, "upstream-sources-stage-")
	if err != nil {
		return fmt.Errorf("creating staged cache dir: %w", err)
	}
	defer func() {
		err = errors.WithDeferred(err, os.RemoveAll(cacheDir))
	}()

	staged.DataDir = cacheDir

	preparedByID := map[uint64]sourcePrepared{}
	for i, prep := range prepared {
		if prep.tmpPath == "" || i >= len(sources) {
			continue
		}

		preparedByID[sources[i].ID] = prep
	}

	for _, src := range sources {
		if !src.Enabled {
			continue
		}

		var data []byte
		if prep, ok := preparedByID[src.ID]; ok {
			data, err = os.ReadFile(prep.tmpPath)
			if err != nil {
				return fmt.Errorf("reading staged source cache: %w", err)
			}
		} else {
			data, err = os.ReadFile(src.path(realDataDir))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("reading current source cache: %w", err)
			} else if err != nil {
				continue
			}
		}

		target := src.path(staged.DataDir)
		mkErr := os.MkdirAll(filepath.Dir(target), aghos.DefaultPermDir)
		if mkErr != nil {
			return fmt.Errorf("creating staged source cache dir: %w", mkErr)
		}

		writeErr := os.WriteFile(target, data, aghos.DefaultPermFile)
		if writeErr != nil {
			return fmt.Errorf("writing staged source cache: %w", writeErr)
		}
	}

	err = s.Reconfigure(ctx, &staged)
	if err != nil {
		return err
	}

	s.serverLock.Lock()
	s.conf.DataDir = realDataDir
	s.upstreamSources.conf.DataDir = realDataDir
	s.serverLock.Unlock()

	return nil
}

func (s *Server) appendUpstreamSourcesForTest(ctx context.Context, upstreams []string) []string {
	if s.conf.UpstreamDNSFileName != "" {
		return upstreams
	}

	sources := s.upstreamSources.all()
	for _, src := range sources {
		if !src.Enabled {
			continue
		}

		data, readErr := os.ReadFile(src.path(s.conf.DataDir))
		if readErr != nil {
			s.logger.WarnContext(ctx, "reading upstream source cache for test", "url", src.URL, slogutil.KeyError, readErr)

			continue
		}

		lines := stringutil.SplitTrimmed(string(data), "\n")
		upstreams = append(upstreams, stringutil.FilterOut(lines, aghnet.IsCommentOrEmpty)...)
	}

	return upstreams
}
