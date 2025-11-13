package filtering

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// upstreamDNSFileJSON is the JSON representation of an upstream DNS file.
type upstreamDNSFileJSON struct {
	URL         string         `json:"url"`
	Name        string         `json:"name"`
	LastUpdated string         `json:"last_updated,omitempty"`
	ID          rulelist.APIID `json:"id"`
	RulesCount  uint64         `json:"rules_count"`
	Enabled     bool           `json:"enabled"`
}

// upstreamDNSConfigJSON is the JSON representation of upstream DNS configuration.
type upstreamDNSConfigJSON struct {
	Files    []upstreamDNSFileJSON `json:"files"`
	Interval uint32                `json:"interval"` // in hours
}

// upstreamDNSFileToJSON converts FilterYAML to upstreamDNSFileJSON.
func upstreamDNSFileToJSON(f FilterYAML) upstreamDNSFileJSON {
	fj := upstreamDNSFileJSON{
		// #nosec G115 -- The overflow is required for backwards compatibility.
		ID:      rulelist.APIID(f.ID),
		Enabled: f.Enabled,
		URL:     f.URL,
		Name:    f.Name,
		// #nosec G115 -- The number of rules must not be negative.
		RulesCount: uint64(f.RulesCount),
	}

	if !f.LastUpdated.IsZero() {
		fj.LastUpdated = f.LastUpdated.Format(time.RFC3339)
	}

	return fj
}

// handleUpstreamDNSStatus handles requests to GET /control/upstream_dns/status.
func (d *DNSFilter) handleUpstreamDNSStatus(w http.ResponseWriter, r *http.Request) {
	resp := upstreamDNSConfigJSON{}

	d.conf.filtersMu.RLock()
	resp.Interval = d.conf.FiltersUpdateIntervalHours
	for _, f := range d.conf.UpstreamDNSFiles {
		fj := upstreamDNSFileToJSON(f)
		resp.Files = append(resp.Files, fj)
	}
	d.conf.filtersMu.RUnlock()

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, resp)
}

// upstreamDNSAddJSON is the request body for adding an upstream DNS file.
type upstreamDNSAddJSON struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// handleUpstreamDNSAddURL handles requests to POST /control/upstream_dns/add_url.
func (d *DNSFilter) handleUpstreamDNSAddURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	fj := upstreamDNSAddJSON{}
	err := json.NewDecoder(r.Body).Decode(&fj)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Failed to parse request body json: %s",
			err,
		)

		return
	}

	err = d.validateFilterURL(fj.URL)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	// Check for duplicates
	d.conf.filtersMu.RLock()
	exists := d.upstreamDNSFileExistsLocked(fj.URL)
	d.conf.filtersMu.RUnlock()

	if exists {
		err = errFilterExists
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Upstream DNS file with URL %q: %s",
			fj.URL,
			err,
		)

		return
	}

	// Set necessary properties
	filt := FilterYAML{
		Enabled:    true,
		URL:        fj.URL,
		Name:       fj.Name,
		isUpstream: true,
		Filter: Filter{
			ID: d.idGen.next(),
		},
	}

	// Download the file contents
	ok, err := d.update(&filt)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Couldn't fetch upstream DNS file from URL %q: %s",
			filt.URL,
			err,
		)

		return
	}

	if !ok {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Upstream DNS file with URL %q is invalid (maybe it points to blank page?)",
			filt.URL,
		)

		return
	}

	// Append to upstream DNS files list
	err = d.upstreamDNSFileAdd(filt)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"Upstream DNS file with URL %q: %s",
			filt.URL,
			err,
		)

		return
	}

	d.conf.ConfModifier.Apply(ctx)

	_, err = fmt.Fprintf(w, "OK %d rules\n", filt.RulesCount)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusInternalServerError,
			"Couldn't write body: %s",
			err,
		)
	}
}

// upstreamDNSRemoveJSON is the request body for removing an upstream DNS file.
type upstreamDNSRemoveJSON struct {
	URL string `json:"url"`
}

// handleUpstreamDNSRemoveURL handles requests to POST /control/upstream_dns/remove_url.
func (d *DNSFilter) handleUpstreamDNSRemoveURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := upstreamDNSRemoveJSON{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			d.logger,
			r,
			w,
			http.StatusBadRequest,
			"failed to parse request body json: %s",
			err,
		)

		return
	}

	var deleted FilterYAML
	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		files := &d.conf.UpstreamDNSFiles

		delIdx := slices.IndexFunc(*files, func(flt FilterYAML) bool {
			return flt.URL == req.URL
		})
		if delIdx == -1 {
			d.logger.ErrorContext(
				ctx,
				"deleting upstream dns file",
				"url", req.URL,
				slogutil.KeyError, errFilterNotExist,
			)

			return
		}

		deleted = (*files)[delIdx]
		p := deleted.Path(d.conf.DataDir)
		err = os.Rename(p, p+".old")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			d.logger.ErrorContext(
				ctx,
				"renaming upstream dns file",
				"id", deleted.ID,
				"path", p,
				slogutil.KeyError, err,
			)

			return
		}

		*files = slices.Delete(*files, delIdx, delIdx+1)

		d.logger.InfoContext(ctx, "deleted upstream dns file", "id", deleted.ID)
	}()

	d.conf.ConfModifier.Apply(ctx)

	_, err = fmt.Fprintf(w, "OK %d rules\n", deleted.RulesCount)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			d.logger,
			r,
			w,
			http.StatusInternalServerError,
			"couldn't write body: %s",
			err,
		)
	}
}

// upstreamDNSSetURLReqData is the data for setting upstream DNS file properties.
type upstreamDNSSetURLReqData struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// upstreamDNSSetURLReq is the request body for setting upstream DNS file.
type upstreamDNSSetURLReq struct {
	Data *upstreamDNSSetURLReqData `json:"data"`
	URL  string                    `json:"url"`
}

// handleUpstreamDNSSetURL handles requests to POST /control/upstream_dns/set_url.
func (d *DNSFilter) handleUpstreamDNSSetURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	fj := upstreamDNSSetURLReq{}
	err := json.NewDecoder(r.Body).Decode(&fj)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	if fj.Data == nil {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusBadRequest,
			"%s",
			errors.Error("data is absent"),
		)

		return
	}

	err = d.validateFilterURL(fj.Data.URL)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "invalid url: %s", err)

		return
	}

	filt := FilterYAML{
		Enabled:    fj.Data.Enabled,
		Name:       fj.Data.Name,
		URL:        fj.Data.URL,
		isUpstream: true,
	}

	restart, err := d.upstreamDNSFileSetProperties(fj.URL, filt)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "%s", err)

		return
	}

	d.conf.ConfModifier.Apply(ctx)
	if restart {
		// No need to restart filtering engine for upstream DNS files
		// They will be picked up on next DNS query
	}
}

// upstreamDNSRefreshReq is the request body for refreshing upstream DNS files.
type upstreamDNSRefreshReq struct{}

// handleUpstreamDNSRefresh handles requests to POST /control/upstream_dns/refresh.
func (d *DNSFilter) handleUpstreamDNSRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	var ok bool
	resp := struct {
		Updated int `json:"updated"`
	}{}
	resp.Updated, _, ok = d.tryRefreshUpstreamDNSFiles(true)
	if !ok {
		aghhttp.ErrorAndLog(
			ctx,
			l,
			r,
			w,
			http.StatusInternalServerError,
			"upstream dns files update procedure is already running",
		)

		return
	}

	aghhttp.WriteJSONResponseOK(ctx, l, w, r, resp)
}

// RegisterUpstreamDNSHandlers registers HTTP handlers for upstream DNS file management.
func (d *DNSFilter) RegisterUpstreamDNSHandlers() {
	registerHTTP := d.conf.HTTPReg.Register

	registerHTTP(http.MethodGet, "/control/upstream_dns/status", d.handleUpstreamDNSStatus)
	registerHTTP(http.MethodPost, "/control/upstream_dns/add_url", d.handleUpstreamDNSAddURL)
	registerHTTP(http.MethodPost, "/control/upstream_dns/remove_url", d.handleUpstreamDNSRemoveURL)
	registerHTTP(http.MethodPost, "/control/upstream_dns/set_url", d.handleUpstreamDNSSetURL)
	registerHTTP(http.MethodPost, "/control/upstream_dns/refresh", d.handleUpstreamDNSRefresh)
}
