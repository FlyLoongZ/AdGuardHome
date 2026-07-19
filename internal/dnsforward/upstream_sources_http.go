package dnsforward

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
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
	LastError   string `json:"last_error,omitempty"`
}

func sourceToJSON(src UpstreamDNSSourceYAML) (sj upstreamSourceJSON) {
	sj = upstreamSourceJSON{
		ID:        src.ID,
		URL:       src.URL,
		Name:      src.Name,
		Enabled:   src.Enabled,
		LastError: src.LastError,
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

type upstreamSourceAddJSON struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type upstreamSourceRemoveJSON struct {
	URL string `json:"url"`
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

// errUpstreamSourcesManagedByFile is returned when upstream source management is
// attempted while the effective upstream configuration is loaded from file.
const errUpstreamSourcesManagedByFile = "upstream_dns_sources are disabled while upstream_dns_file is set"

// checkUpstreamSourcesMutable returns an error if upstream source management is
// disabled because the effective upstream configuration is loaded from file.
func (s *Server) checkUpstreamSourcesMutable() (err error) {
	if s.conf.UpstreamDNSFileName != "" {
		return errors.Error(errUpstreamSourcesManagedByFile)
	}

	return nil
}

func (s *Server) handleUpstreamSourcesStatus(w http.ResponseWriter, r *http.Request) {
	s.upstreamSourcesMu.RLock()
	sources := s.upstreamSources.all()
	s.upstreamSourcesMu.RUnlock()

	aghhttp.WriteJSONResponseOK(r.Context(), s.logger, w, r, upstreamSourceStatusResp{
		Sources: sourcesToJSON(sources),
	})
}

func applyUpstreamSourceStage(
	s *Server,
	ctx context.Context,
	stage sourceStageResult,
) (err error) {
	if stage.staged == nil {
		return nil
	}

	// Keep a stable manager reference: reconfigure recreates upstreamSources,
	// but rollback/cleanup must still use the manager that owns the cache files.
	sm := s.upstreamSources

	// Snapshot the pre-update list so cache files for removed sources can still
	// be deleted after a successful reconfigure replaces upstreamSources.
	prevSources := sm.cloneSources()

	// Commit caches first so reconfigure always reads the final cache paths.
	// Keep rollback records until reconfigure succeeds.
	records, err := sm.commitPrepared(stage.staged, stage.prepared)
	if err != nil {
		return err
	}

	if stage.requiresRestart {
		err = s.reconfigureWithUpstreamSources(ctx, stage.staged)
		if err != nil {
			// reconfigureLocked may already have restored conf while the new
			// caches were still on disk, so metadata and loaded upstream rules
			// can still reflect the failed update.  Restore the previous cache
			// files first, then reload so runtime state matches the backups.
			sm.rollbackCommitted(records)
			if reloadErr := s.reconfigureLocked(ctx, nil); reloadErr != nil {
				s.logger.ErrorContext(
					ctx,
					"reloading after upstream source cache rollback",
					slogutil.KeyError, reloadErr,
				)
			}

			return err
		}
	}

	// Prefer the live manager after reconfigure so conf pointers stay in sync.
	live := s.upstreamSources
	if live == nil {
		live = sm
	}
	live.finalizeRemoved(prevSources, stage.staged)

	// Protect s.conf readers such as WriteDiskConfig/getDNSConfig.  Keep the
	// existing lock order: upstreamSourcesMu (held by caller) then serverLock.
	s.serverLock.Lock()
	live.conf.UpstreamDNSSources = stage.staged
	s.conf.UpstreamDNSSources = stage.staged
	confModifier := s.conf.ConfModifier
	s.serverLock.Unlock()

	confModifier.Apply(ctx)
	sm.cleanupCommitBackups(records)

	return nil
}

func (s *Server) handleUpstreamSourcesAddURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.checkUpstreamSourcesMutable(); err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	req := &upstreamSourceAddJSON{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	// Download outside the lock so long network I/O does not block other
	// source operations or DNS reconfiguration.
	src := UpstreamDNSSourceYAML{Enabled: true, URL: req.URL, Name: req.Name}
	p, err := s.upstreamSources.prepare(ctx, src)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	stage, err := s.upstreamSources.stageAddPrepared(src, p)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	err = applyUpstreamSourceStage(s, ctx, stage)
	if err != nil {
		s.upstreamSources.cleanupPrepared(stage.prepared)
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	aghhttp.OK(ctx, s.logger, w)
}

func (s *Server) handleUpstreamSourcesRemoveURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.checkUpstreamSourcesMutable(); err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	req := &upstreamSourceRemoveJSON{}
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

	err = applyUpstreamSourceStage(s, ctx, stage)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	aghhttp.OK(ctx, s.logger, w)
}

// errUpstreamSourceChanged is returned when a set operation's prepared result
// no longer matches the live source list, typically because another concurrent
// update raced with this request.
const errUpstreamSourceChanged = errors.Error("upstream source changed, please retry")

func (s *Server) handleUpstreamSourcesSetURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.checkUpstreamSourcesMutable(); err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

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

	s.upstreamSourcesMu.RLock()
	current, found := s.upstreamSources.byURL(req.URL)
	s.upstreamSourcesMu.RUnlock()
	if !found {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", errors.Error("url doesn't exist"))

		return
	}

	enabled := current.Enabled
	if req.Data.Enabled != nil {
		enabled = *req.Data.Enabled
	}
	data := UpstreamDNSSourceYAML{
		Name:    req.Data.Name,
		URL:     req.Data.URL,
		Enabled: enabled,
	}

	// Optimistic plan outside the write lock so downloads do not block other
	// source operations.  The final plan is recomputed under the write lock.
	s.upstreamSourcesMu.RLock()
	plan, err := s.upstreamSources.planSet(req.URL, data)
	s.upstreamSourcesMu.RUnlock()
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	var prepared sourcePrepared
	var preparedURL string
	if plan.needsPrepare {
		toFetch := plan.current.clone()
		toFetch.URL = data.URL
		toFetch.Name = data.Name
		toFetch.Enabled = data.Enabled
		prepared, err = s.upstreamSources.prepare(ctx, toFetch)
		if err != nil {
			aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

			return
		}
		preparedURL = data.URL
	}

	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	// Recompute against the live list so concurrent updates cannot apply a
	// stale plan after the lock-free prepare window.
	plan, err = s.upstreamSources.planSet(req.URL, data)
	if err != nil {
		if prepared.tmpPath != "" {
			_ = os.Remove(prepared.tmpPath)
		}
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if plan.current.ID != current.ID {
		if prepared.tmpPath != "" {
			_ = os.Remove(prepared.tmpPath)
		}
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusConflict, "%s", errUpstreamSourceChanged)

		return
	}

	if plan.needsPrepare {
		if prepared.tmpPath == "" || preparedURL != plan.data.URL {
			if prepared.tmpPath != "" {
				_ = os.Remove(prepared.tmpPath)
			}
			aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusConflict, "%s", errUpstreamSourceChanged)

			return
		}
	} else if prepared.tmpPath != "" {
		// Final plan no longer requires a download; discard the prepared file.
		_ = os.Remove(prepared.tmpPath)
		prepared = sourcePrepared{}
	}

	stage, err := s.upstreamSources.stageSetPrepared(plan, prepared)
	if err != nil {
		if prepared.tmpPath != "" {
			_ = os.Remove(prepared.tmpPath)
		}
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if stage.staged == nil {
		aghhttp.OK(ctx, s.logger, w)

		return
	}

	err = applyUpstreamSourceStage(s, ctx, stage)
	if err != nil {
		s.upstreamSources.cleanupPrepared(stage.prepared)
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	aghhttp.OK(ctx, s.logger, w)
}

func (s *Server) handleUpstreamSourcesRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.checkUpstreamSourcesMutable(); err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	stage, err := s.refreshUpstreamSources(ctx, true)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	for _, warn := range stage.warnings {
		s.logger.WarnContext(ctx, "refreshing upstream source", slogutil.KeyError, warn)
	}

	aghhttp.WriteJSONResponseOK(ctx, s.logger, w, r, struct {
		Updated int `json:"updated"`
	}{Updated: stage.updated})
}

func (s *Server) reconfigureWithUpstreamSources(
	ctx context.Context,
	sources []UpstreamDNSSourceYAML,
) (err error) {
	s.serverLock.RLock()
	staged := s.conf
	s.serverLock.RUnlock()

	staged.UpstreamDNSSources = slices.Clone(sources)

	return s.reconfigureLocked(ctx, &staged)
}

// refreshUpstreamSources downloads enabled sources outside the lock, then
// commits under upstreamSourcesMu.  When force is false, sources that have not
// yet reached the shared filters update interval are skipped.
func (s *Server) refreshUpstreamSources(ctx context.Context, force bool) (stage sourceStageResult, err error) {
	s.upstreamSourcesMu.RLock()
	snapshot := s.upstreamSources.all()
	intervalHours := s.upstreamSources.updateIntervalHours()
	s.upstreamSourcesMu.RUnlock()

	preparedByID := map[uint64]sourcePrepared{}
	warnings := []error{}
	// failedByID records per-source prepare failures so they can be written
	// back to LastError under the write lock.
	failedByID := map[uint64]string{}
	refreshed := 0

	for _, src := range snapshot {
		if !shouldRefresh(src, intervalHours, force) {
			continue
		}

		p, prepErr := s.upstreamSources.prepare(ctx, src)
		if prepErr != nil {
			warn := fmt.Errorf("preparing source %q: %w", src.URL, prepErr)
			warnings = append(warnings, warn)
			failedByID[src.ID] = prepErr.Error()

			continue
		}

		// Remember the snapshot checksum so stageRefreshPrepared can drop this
		// result if a concurrent update already replaced the source.
		p.prevChecksum = src.checksum
		preparedByID[src.ID] = p
		refreshed++
	}

	s.upstreamSourcesMu.Lock()
	defer s.upstreamSourcesMu.Unlock()

	// Persist prepare failures on the live source list even when no successful
	// prepare remains to apply.
	for i := range s.conf.UpstreamDNSSources {
		src := &s.conf.UpstreamDNSSources[i]
		if msg, ok := failedByID[src.ID]; ok {
			src.LastError = msg
		}
	}

	if refreshed == 0 {
		if len(warnings) > 0 {
			for _, p := range preparedByID {
				if p.tmpPath != "" {
					_ = os.Remove(p.tmpPath)
				}
			}

			return stage, errors.Join(warnings...)
		}

		return stage, nil
	}

	stage = s.upstreamSources.stageRefreshPrepared(preparedByID, warnings)
	err = applyUpstreamSourceStage(s, ctx, stage)
	if err != nil {
		s.upstreamSources.cleanupPrepared(stage.prepared)

		return stage, err
	}

	return stage, nil
}

// RefreshUpstreamSources refreshes enabled upstream DNS sources.  force bypasses
// the shared filters_update_interval expiry.  It is safe for concurrent use and
// is intended to be triggered by the filtering update loop.
func (s *Server) RefreshUpstreamSources(ctx context.Context, force bool) {
	if s == nil {
		return
	}

	if err := s.checkUpstreamSourcesMutable(); err != nil {
		return
	}

	stage, err := s.refreshUpstreamSources(ctx, force)
	if err != nil {
		s.logger.WarnContext(ctx, "refreshing upstream sources", slogutil.KeyError, err)

		return
	}

	for _, warn := range stage.warnings {
		s.logger.WarnContext(ctx, "refreshing upstream source", slogutil.KeyError, warn)
	}

	if stage.updated > 0 {
		s.logger.InfoContext(ctx, "upstream sources refreshed", "updated", stage.updated)
	}
}

// appendUpstreamSourcesForTest appends enabled upstream DNS sources to the list
// for testing.  Note that when upstream_dns_file is set, the caller
// (handleTestUpstreamDNS) replaces upstreams entirely with the file contents,
// so this function is not called in that path.
func (s *Server) appendUpstreamSourcesForTest(ctx context.Context, upstreams []string) []string {
	s.upstreamSourcesMu.RLock()
	sources := s.upstreamSources.all()
	s.upstreamSourcesMu.RUnlock()
	for _, src := range sources {
		if !src.Enabled {
			continue
		}

		data, readErr := os.ReadFile(src.path(s.upstreamSources.dataDir))
		if readErr != nil {
			s.logger.WarnContext(ctx, "reading upstream source cache for test", "url", src.URL, slogutil.KeyError, readErr)

			continue
		}

		lines := stringutil.SplitTrimmed(string(data), "\n")
		upstreams = append(upstreams, stringutil.FilterOut(lines, aghnet.IsCommentOrEmpty)...)
	}

	return upstreams
}
