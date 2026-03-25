package dnsforward

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
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

	_, err = s.upstreamSources.add(ctx, UpstreamDNSSourceYAML{Enabled: true, URL: req.URL, Name: req.Name})
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)
	if reErr := s.Reconfigure(ctx, nil); reErr != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

		return
	}

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

	_, err = s.upstreamSources.remove(req.URL)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)
	if reErr := s.Reconfigure(ctx, nil); reErr != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

		return
	}

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

	_, err = s.upstreamSources.set(ctx, req.URL, UpstreamDNSSourceYAML{
		Name:    req.Data.Name,
		URL:     req.Data.URL,
		Enabled: enabled,
	})
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)
	if reErr := s.Reconfigure(ctx, nil); reErr != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

		return
	}

	aghhttp.OK(ctx, s.logger, w)
}

func (s *Server) handleUpstreamSourcesRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	updated, err := s.upstreamSources.refresh(ctx, true)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	s.conf.ConfModifier.Apply(ctx)
	if reErr := s.Reconfigure(ctx, nil); reErr != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", reErr)

		return
	}

	aghhttp.WriteJSONResponseOK(ctx, s.logger, w, r, struct {
		Updated int `json:"updated"`
	}{Updated: updated})
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

		data, readErr := os.ReadFile(src.path())
		if readErr != nil {
			s.logger.WarnContext(ctx, "reading upstream source cache for test", "url", src.URL, slogutil.KeyError, readErr)

			continue
		}

		lines := stringutil.SplitTrimmed(string(data), "\n")
		upstreams = append(upstreams, stringutil.FilterOut(lines, aghnet.IsCommentOrEmpty)...)
	}

	return upstreams
}
