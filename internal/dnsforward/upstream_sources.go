package dnsforward

import (
	"bufio"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/cespare/xxhash/v2"
)

// upstreamSourcesCacheDir is the subdirectory under the filtering data
// directory used for upstream source caches.  It is intentionally separate
// from filtering-rule lists (filters/) so the two never overwrite each other.
const upstreamSourcesCacheDir = "upstream_sources"

// legacyUpstreamSourcesCacheDir is the old cache location that shared the
// filtering-rule list directory.  Existing installs are migrated on startup.
const legacyUpstreamSourcesCacheDir = "filters"

// maxUpstreamSourceSize is the maximum size of an upstream source list.  It
// matches the default filtering-rule list limit so large downloads cannot
// exhaust memory during prepare.
//
// Tests may temporarily lower this value.
var maxUpstreamSourceSize int64 = 64 << 20

// UpstreamDNSSource represents source metadata persisted in YAML.
type UpstreamDNSSource struct {
	// ID is automatically assigned when source is added.
	ID uint64 `yaml:"id"`
}

// UpstreamDNSSourceYAML represents a single upstream source in config.
type UpstreamDNSSourceYAML struct {
	Enabled     bool      `yaml:"enabled"`
	URL         string    `yaml:"url"`
	Name        string    `yaml:"name"`
	RulesCount  int       `yaml:"-"`
	LastUpdated time.Time `yaml:"-"`
	// LastError is the last non-fatal load/refresh error for this source.  It
	// is exposed via the status API so operators can see when an enabled
	// source failed to load without scanning logs.
	LastError string `yaml:"-"`
	checksum  uint64

	UpstreamDNSSource `yaml:",inline"`
}

// path returns the cache file path for source contents.
func (s *UpstreamDNSSourceYAML) path(dataDir string) string {
	return filepath.Join(
		dataDir,
		upstreamSourcesCacheDir,
		strconv.FormatUint(s.ID, 10)+".txt",
	)
}

// legacyPath returns the pre-migration cache path that lived next to filtering
// rule lists.
func (s *UpstreamDNSSourceYAML) legacyPath(dataDir string) string {
	return filepath.Join(
		dataDir,
		legacyUpstreamSourcesCacheDir,
		strconv.FormatUint(s.ID, 10)+".txt",
	)
}

// ensureName sets name to title or generated fallback.
func (s *UpstreamDNSSourceYAML) ensureName(title string) {
	if s.Name != "" {
		return
	}

	if title != "" {
		s.Name = title

		return
	}

	s.Name = fmt.Sprintf("List %d", s.ID)
}

func (s *UpstreamDNSSourceYAML) clear() {
	s.RulesCount = 0
	s.LastUpdated = time.Time{}
	s.LastError = ""
	s.checksum = 0
}

func (s *UpstreamDNSSourceYAML) clone() (clone UpstreamDNSSourceYAML) {
	clone = *s

	return clone
}

type sourcePrepared struct {
	tmpPath      string
	count        int
	checksum     uint64
	prevChecksum uint64
	name         string
	lastUpdated  time.Time
}

// commitRecord describes a cache file replacement performed by commit.  It is
// used to roll the filesystem back when a later step (for example reconfigure)
// fails after caches have already been written.
type commitRecord struct {
	// dst is the final cache path upstream_sources/{id}.txt.
	dst string
	// backup is dst+".old" when an existing cache was moved aside; empty when
	// the cache file was newly created.
	backup string
	// created is true when dst did not exist before the commit.
	created bool
}

type sourceStageResult struct {
	staged          []UpstreamDNSSourceYAML
	prepared        []sourcePrepared
	requiresRestart bool
	updated         int
	warnings        []error
}

// sourceManager manages upstream DNS source lists and their cached contents.
type sourceManager struct {
	conf   *ServerConfig
	logger *slog.Logger
	// filter provides the shared data directory, HTTP client, SafeFS patterns,
	// and list ID generator used by filtering-rule lists.
	filter *filtering.DNSFilter

	dataDir        string
	httpClient     *http.Client
	safeFSPatterns []string
}

func newSourceManager(conf *ServerConfig, l *slog.Logger, f *filtering.DNSFilter) *sourceManager {
	sm := &sourceManager{
		conf:   conf,
		logger: l,
		filter: f,
	}

	if f != nil {
		sm.dataDir = f.DataDir()
		sm.httpClient = f.HTTPClient()
		sm.safeFSPatterns = f.SafeFSPatterns()
	}
	if sm.httpClient == nil {
		sm.httpClient = http.DefaultClient
	}

	if conf != nil {
		for i := range conf.UpstreamDNSSources {
			src := &conf.UpstreamDNSSources[i]
			if f != nil && src.ID != 0 {
				// Keep IDs unique across filter lists and upstream sources so
				// configuration remains unambiguous even though cache files
				// now live in separate directories.
				f.ReserveListID(src.ID)
			}

			sm.migrateLegacyCache(src)

			err := sm.loadMetadata(src)
			if err != nil {
				src.LastError = err.Error()
				l.Warn("loading upstream source cache metadata", "url", src.URL, slogutil.KeyError, err)
			} else if src.LastUpdated.IsZero() {
				l.Debug("no cached metadata for upstream source, will fetch on next refresh", "url", src.URL)
			}
		}
	}

	sm.cleanupStaleCacheFiles()

	return sm
}

// migrateLegacyCache moves a source cache from the old filters/ directory into
// upstream_sources/ when needed.  Failures are logged and non-fatal.
func (m *sourceManager) migrateLegacyCache(src *UpstreamDNSSourceYAML) {
	if m.dataDir == "" || src == nil || src.ID == 0 {
		return
	}

	dst := src.path(m.dataDir)
	if _, err := os.Stat(dst); err == nil {
		return
	} else if err != nil && !stderrors.Is(err, os.ErrNotExist) {
		m.logger.Warn(
			"checking upstream source cache",
			"path", dst,
			slogutil.KeyError, err,
		)

		return
	}

	legacy := src.legacyPath(m.dataDir)
	if _, err := os.Stat(legacy); err != nil {
		return
	}

	if err := os.MkdirAll(m.cacheDir(), aghos.DefaultPermDir); err != nil {
		m.logger.Warn(
			"creating upstream source cache dir for migration",
			"path", m.cacheDir(),
			slogutil.KeyError, err,
		)

		return
	}

	if err := os.Rename(legacy, dst); err != nil {
		m.logger.Warn(
			"migrating upstream source cache",
			"from", legacy,
			"to", dst,
			slogutil.KeyError, err,
		)

		return
	}

	m.logger.Info(
		"migrated upstream source cache",
		"from", legacy,
		"to", dst,
	)

	// Drop leftover backup next to the legacy path, if any.
	_ = os.Remove(legacy + ".old")
}

func (m *sourceManager) cacheDir() string {
	return filepath.Join(m.dataDir, upstreamSourcesCacheDir)
}

// openSource returns a reader for a remote URL or a local absolute file path.
// Local paths are restricted by the filtering SafeFS patterns.  ctx controls
// cancellation of remote downloads.
func (m *sourceManager) openSource(ctx context.Context, srcURL string) (r io.ReadCloser, err error) {
	if filepath.IsAbs(srcURL) {
		path := filepath.Clean(srcURL)
		if !filtering.PathMatchesAny(m.safeFSPatterns, path) {
			return nil, fmt.Errorf("path %q does not match safe patterns", path)
		}

		r, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening file: %w", err)
		}

		return r, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading from url: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("got status code %d, want %d", resp.StatusCode, http.StatusOK)
	}

	return resp.Body, nil
}

func (m *sourceManager) validateLines(lines []string) (err error) {
	if len(lines) == 0 {
		return nil
	}

	_, err = proxy.ParseUpstreamsConfig(lines, &upstream.Options{Logger: slogutil.NewDiscardLogger()})
	if err != nil {
		return fmt.Errorf("validating upstream source rules: %w", err)
	}

	return nil
}

func (m *sourceManager) prepare(ctx context.Context, src UpstreamDNSSourceYAML) (p sourcePrepared, err error) {
	err = os.MkdirAll(m.cacheDir(), aghos.DefaultPermDir)
	if err != nil {
		return p, fmt.Errorf("creating cache dir: %w", err)
	}

	if m.dataDir == "" {
		return p, errors.New("filtering data directory is not configured")
	}

	r, err := m.openSource(ctx, src.URL)
	if err != nil {
		return p, err
	}
	defer func() {
		err = errors.WithDeferred(err, r.Close())
	}()

	tmpFile, err := os.CreateTemp(m.cacheDir(), "src-*.tmp")
	if err != nil {
		return p, fmt.Errorf("creating temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmpFile.Name())
		}
	}()
	defer func() {
		err = errors.WithDeferred(err, tmpFile.Close())
	}()

	h := xxhash.New()
	writer := io.MultiWriter(tmpFile, h)
	// +1 lets us detect an oversized body after the limited read finishes.
	lr := &io.LimitedReader{R: r, N: maxUpstreamSourceSize + 1}
	tr := io.TeeReader(lr, writer)

	var lines []string
	lineCount := 0
	scanner := bufio.NewScanner(tr)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !aghnet.IsCommentOrEmpty(line) {
			lineCount++
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return p, fmt.Errorf("reading source: %w", err)
	}
	if lr.N == 0 {
		return p, fmt.Errorf("upstream source exceeds maximum size of %d bytes", maxUpstreamSourceSize)
	}

	err = m.validateLines(lines)
	if err != nil {
		return p, err
	}

	title := ""
	if filepath.IsAbs(src.URL) {
		title = filepath.Base(src.URL)
	}

	checksum := h.Sum64()

	p = sourcePrepared{
		tmpPath:     tmpFile.Name(),
		count:       lineCount,
		checksum:    checksum,
		name:        title,
		lastUpdated: time.Now(),
	}

	return p, nil
}

func (m *sourceManager) commit(src *UpstreamDNSSourceYAML, p sourcePrepared) (rec commitRecord, updated bool, err error) {
	dst := src.path(m.dataDir)

	if p.checksum == p.prevChecksum {
		_, statErr := os.Stat(dst)
		if statErr == nil {
			// Cache exists and content is unchanged; skip rewrite but advance
			// mtime so loadMetadata restores the same LastUpdated after restart.
			_ = os.Remove(p.tmpPath)
			if chtErr := os.Chtimes(dst, p.lastUpdated, p.lastUpdated); chtErr != nil {
				m.logger.ErrorContext(
					context.Background(),
					"updating source cache mtime",
					"path", dst,
					slogutil.KeyError, chtErr,
				)
			}

			src.ensureName(p.name)
			src.RulesCount = p.count
			src.checksum = p.checksum
			src.LastUpdated = p.lastUpdated
			src.LastError = ""

			return rec, false, nil
		}

		if !stderrors.Is(statErr, os.ErrNotExist) {
			return rec, false, fmt.Errorf("checking source cache: %w", statErr)
		}

		// Cache is missing; rebuild it from the prepared temporary file.
	}

	rec.dst = dst

	_, statErr := os.Stat(dst)
	switch {
	case statErr == nil:
		backup := dst + ".old"
		// Drop a leftover backup from a previous interrupted update.
		_ = os.Remove(backup)
		err = os.Rename(dst, backup)
		if err != nil {
			return commitRecord{}, false, fmt.Errorf("backing up source cache: %w", err)
		}
		rec.backup = backup
	case stderrors.Is(statErr, os.ErrNotExist):
		rec.created = true
	default:
		return commitRecord{}, false, fmt.Errorf("checking source cache: %w", statErr)
	}

	err = os.Rename(p.tmpPath, dst)
	if err != nil {
		if rec.backup != "" {
			_ = os.Rename(rec.backup, dst)
		}

		return commitRecord{}, false, fmt.Errorf("renaming source cache: %w", err)
	}

	src.ensureName(p.name)
	src.RulesCount = p.count
	src.checksum = p.checksum
	src.LastUpdated = p.lastUpdated
	src.LastError = ""

	return rec, true, nil
}

func (m *sourceManager) cleanupPrepared(prepared []sourcePrepared) {
	for _, p := range prepared {
		if p.tmpPath == "" {
			continue
		}

		_ = os.Remove(p.tmpPath)
	}
}

// rollbackCommitted restores cache files described by records after a failed
// apply.  records should be processed in reverse order so multi-source commits
// unwind cleanly.
func (m *sourceManager) rollbackCommitted(records []commitRecord) {
	for i := len(records) - 1; i >= 0; i-- {
		rec := records[i]
		if rec.dst == "" {
			continue
		}

		if rec.created {
			if rmErr := os.Remove(rec.dst); rmErr != nil && !stderrors.Is(rmErr, os.ErrNotExist) {
				m.logger.ErrorContext(
					context.Background(),
					"rolling back created source cache",
					"path", rec.dst,
					slogutil.KeyError, rmErr,
				)
			}

			continue
		}

		if rec.backup == "" {
			continue
		}

		// Replace the newly written cache with the pre-commit backup.
		_ = os.Remove(rec.dst)
		if mvErr := os.Rename(rec.backup, rec.dst); mvErr != nil {
			m.logger.ErrorContext(
				context.Background(),
				"rolling back source cache backup",
				"path", rec.dst,
				"backup", rec.backup,
				slogutil.KeyError, mvErr,
			)
		}
	}
}

// cleanupCommitBackups removes temporary .old backups left after a successful
// commit transaction.
func (m *sourceManager) cleanupCommitBackups(records []commitRecord) {
	for _, rec := range records {
		if rec.backup == "" {
			continue
		}

		if rmErr := os.Remove(rec.backup); rmErr != nil && !stderrors.Is(rmErr, os.ErrNotExist) {
			m.logger.ErrorContext(
				context.Background(),
				"removing source cache backup",
				"path", rec.backup,
				slogutil.KeyError, rmErr,
			)
		}
	}
}

func (m *sourceManager) loadMetadata(src *UpstreamDNSSourceYAML) (err error) {
	fileName := src.path(m.dataDir)

	file, err := os.Open(fileName)
	if stderrors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("opening source file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	st, err := file.Stat()
	if err != nil {
		return fmt.Errorf("getting source file stat: %w", err)
	}

	h := xxhash.New()
	tr := io.TeeReader(file, h)

	lineCount := 0
	scanner := bufio.NewScanner(tr)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !aghnet.IsCommentOrEmpty(line) {
			lineCount++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading source file: %w", err)
	}

	src.RulesCount = lineCount
	src.checksum = h.Sum64()
	src.LastUpdated = st.ModTime()

	if filepath.IsAbs(src.URL) {
		src.ensureName(filepath.Base(src.URL))
	}

	return nil
}

func (m *sourceManager) cloneSources() (sources []UpstreamDNSSourceYAML) {
	sources = make([]UpstreamDNSSourceYAML, len(m.conf.UpstreamDNSSources))
	copy(sources, m.conf.UpstreamDNSSources)

	return sources
}

func (m *sourceManager) commitPrepared(
	staged []UpstreamDNSSourceYAML,
	prepared []sourcePrepared,
) (records []commitRecord, err error) {
	for i := range prepared {
		if prepared[i].tmpPath == "" {
			continue
		}

		if i >= len(staged) {
			continue
		}

		var rec commitRecord
		rec, _, err = m.commit(&staged[i], prepared[i])
		if err != nil {
			m.rollbackCommitted(records)
			m.cleanupPrepared(prepared[i:])

			return nil, err
		}
		prepared[i].tmpPath = ""
		if rec.dst != "" {
			records = append(records, rec)
		}
	}

	return records, nil
}

// finalizeRemoved deletes cache files of sources that were present in prev but
// are no longer present in staged.  prev must be the source list from before
// the update is applied; after a successful reconfigure the live config already
// matches staged, so the pre-update snapshot is required for cleanup.
func (m *sourceManager) finalizeRemoved(prev, staged []UpstreamDNSSourceYAML) {
	for _, cur := range prev {
		if slices.ContainsFunc(staged, func(src UpstreamDNSSourceYAML) bool { return src.ID == cur.ID }) {
			continue
		}

		src := &UpstreamDNSSourceYAML{UpstreamDNSSource: UpstreamDNSSource{ID: cur.ID}}
		for _, path := range []string{src.path(m.dataDir), src.legacyPath(m.dataDir)} {
			if rmErr := os.Remove(path); rmErr != nil && !stderrors.Is(rmErr, os.ErrNotExist) {
				m.logger.ErrorContext(context.Background(), "removing source cache", "path", path, slogutil.KeyError, rmErr)
			}

			// Also drop any leftover backup files from older versions or failed applies.
			oldPath := path + ".old"
			if rmErr := os.Remove(oldPath); rmErr != nil && !stderrors.Is(rmErr, os.ErrNotExist) {
				m.logger.ErrorContext(context.Background(), "removing source cache backup", "path", oldPath, slogutil.KeyError, rmErr)
			}
		}
	}
}

// cleanupStaleCacheFiles removes leftover temporary cache files under the
// upstream source cache directory.  Active {id}.txt.old commit backups are
// preserved so a reconfigure that recreates the manager cannot destroy an
// in-flight rollback transaction; those backups are removed by
// cleanupCommitBackups or finalizeRemoved after the transaction settles.
func (m *sourceManager) cleanupStaleCacheFiles() {
	if m.dataDir == "" {
		return
	}

	patterns := []string{
		filepath.Join(m.cacheDir(), "src-*.tmp"),
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, path := range matches {
			_ = os.Remove(path)
		}
	}
}

// stageAddPrepared merges a successfully prepared source into the current list.
// The caller may prepare outside the lock; this method only performs local
// validation and staging and must be called under upstreamSourcesMu.
func (m *sourceManager) stageAddPrepared(src UpstreamDNSSourceYAML, p sourcePrepared) (res sourceStageResult, err error) {
	if slices.ContainsFunc(m.conf.UpstreamDNSSources, func(cur UpstreamDNSSourceYAML) bool { return cur.URL == src.URL }) {
		_ = os.Remove(p.tmpPath)

		return res, errors.New("url already exists")
	}

	staged := m.cloneSources()
	prepared := make([]sourcePrepared, len(staged)+1)

	if m.filter == nil {
		_ = os.Remove(p.tmpPath)

		return res, errors.New("dns filter is not initialized")
	}

	src.ID = m.filter.NextListID()
	if src.ID == 0 {
		_ = os.Remove(p.tmpPath)

		return res, errors.New("failed to allocate source id")
	}
	p.prevChecksum = 0

	src.ensureName(p.name)
	src.RulesCount = p.count
	src.checksum = p.checksum
	src.LastUpdated = p.lastUpdated
	src.LastError = ""

	staged = append(staged, src)
	prepared[len(staged)-1] = p

	res = sourceStageResult{
		staged:          staged,
		prepared:        prepared,
		requiresRestart: src.Enabled,
		updated:         boolToInt(src.Enabled),
	}

	return res, nil
}

func (m *sourceManager) stageRemove(srcURL string) (res sourceStageResult, err error) {
	staged := m.cloneSources()
	idx := slices.IndexFunc(staged, func(src UpstreamDNSSourceYAML) bool { return src.URL == srcURL })
	if idx < 0 {
		return res, errors.New("url doesn't exist")
	}

	removedEnabled := staged[idx].Enabled
	staged = slices.Delete(staged, idx, idx+1)

	res = sourceStageResult{
		staged:          staged,
		requiresRestart: removedEnabled,
	}

	return res, nil
}

// setPlan describes a source update after inspecting the current state.
type setPlan struct {
	oldURL           string
	data             UpstreamDNSSourceYAML
	current          UpstreamDNSSourceYAML
	needsPrepare     bool
	metadataChanged  bool
	semanticChanged  bool
	prevEnabled      bool
}

// planSet inspects the current source list and returns whether a download is
// required.  It must be called under a read or write lock that protects the
// source list.
func (m *sourceManager) planSet(oldURL string, data UpstreamDNSSourceYAML) (plan setPlan, err error) {
	idx := slices.IndexFunc(m.conf.UpstreamDNSSources, func(src UpstreamDNSSourceYAML) bool {
		return src.URL == oldURL
	})
	if idx < 0 {
		return plan, errors.New("url doesn't exist")
	}

	if oldURL != data.URL && slices.ContainsFunc(m.conf.UpstreamDNSSources, func(src UpstreamDNSSourceYAML) bool {
		return src.URL == data.URL
	}) {
		return plan, errors.New("url already exists")
	}

	current := m.conf.UpstreamDNSSources[idx]
	plan = setPlan{
		oldURL:      oldURL,
		data:        data,
		current:     current.clone(),
		prevEnabled: current.Enabled,
	}

	if current.Name != data.Name {
		plan.metadataChanged = true
	}
	if current.URL != data.URL {
		plan.semanticChanged = true
		plan.needsPrepare = data.Enabled
	}
	if current.Enabled != data.Enabled {
		plan.semanticChanged = true
		plan.needsPrepare = data.Enabled
	}

	return plan, nil
}

// stageSetPrepared applies a previously computed set plan.  prepared may be
// empty when no download was required.  Must be called under upstreamSourcesMu.
// The plan must have been recomputed against the live source list immediately
// before this call so concurrent updates cannot apply a stale snapshot.
func (m *sourceManager) stageSetPrepared(plan setPlan, prepared sourcePrepared) (res sourceStageResult, err error) {
	staged := m.cloneSources()
	idx := slices.IndexFunc(staged, func(src UpstreamDNSSourceYAML) bool { return src.URL == plan.oldURL })
	if idx < 0 {
		if prepared.tmpPath != "" {
			_ = os.Remove(prepared.tmpPath)
		}

		return res, errors.New("url doesn't exist")
	}

	if staged[idx].ID != plan.current.ID {
		if prepared.tmpPath != "" {
			_ = os.Remove(prepared.tmpPath)
		}

		return res, errors.Error("upstream source changed, please retry")
	}

	if plan.oldURL != plan.data.URL && slices.ContainsFunc(staged, func(src UpstreamDNSSourceYAML) bool {
		return src.URL == plan.data.URL
	}) {
		if prepared.tmpPath != "" {
			_ = os.Remove(prepared.tmpPath)
		}

		return res, errors.New("url already exists")
	}

	src := staged[idx]
	preparedList := make([]sourcePrepared, len(staged))

	if src.Name != plan.data.Name {
		src.Name = plan.data.Name
	}
	if src.URL != plan.data.URL {
		src.URL = plan.data.URL
		src.clear()
	}
	if src.Enabled != plan.data.Enabled {
		src.Enabled = plan.data.Enabled
		if !plan.data.Enabled {
			src.clear()
		}
	}

	hadContentChange := false
	if plan.needsPrepare {
		if prepared.tmpPath == "" {
			return res, errors.New("prepared source is missing")
		}

		prepared.prevChecksum = src.checksum
		hadContentChange = prepared.checksum != src.checksum
		src.ensureName(prepared.name)
		src.RulesCount = prepared.count
		src.checksum = prepared.checksum
		src.LastUpdated = prepared.lastUpdated
		src.LastError = ""
		preparedList[idx] = prepared
	}

	staged[idx] = src

	res = sourceStageResult{
		staged:          staged,
		prepared:        preparedList,
		requiresRestart: (plan.semanticChanged && (plan.prevEnabled || src.Enabled)) || hadContentChange,
		updated:         boolToInt(hadContentChange),
	}

	if !plan.metadataChanged && !plan.semanticChanged {
		res.staged = nil
	}

	return res, nil
}

// stageRefreshPrepared merges prepared refresh results for sources that are
// still present and enabled.  Must be called under upstreamSourcesMu.
func (m *sourceManager) stageRefreshPrepared(
	preparedByID map[uint64]sourcePrepared,
	warnings []error,
) (res sourceStageResult) {
	staged := m.cloneSources()
	prepared := make([]sourcePrepared, len(staged))
	updated := 0
	refreshed := 0

	for i := range staged {
		src := &staged[i]
		if !src.Enabled {
			continue
		}

		p, ok := preparedByID[src.ID]
		if !ok {
			continue
		}

		// The download was based on a lock-free snapshot.  If another update
		// already changed this source, drop the stale prepare instead of
		// overwriting the newer content.
		if p.prevChecksum != src.checksum {
			if p.tmpPath != "" {
				_ = os.Remove(p.tmpPath)
			}

			continue
		}

		refreshed++
		wasUpdated := p.checksum != src.checksum

		src.ensureName(p.name)
		src.RulesCount = p.count
		src.checksum = p.checksum
		// Always advance LastUpdated after a successful refresh attempt so the
		// shared filters_update_interval expiry works even when content is
		// unchanged, matching filtering-rule list behaviour.
		src.LastUpdated = p.lastUpdated
		src.LastError = ""
		prepared[i] = p

		if wasUpdated {
			updated++
		}
	}

	// Drop prepared files that no longer map to an active source.
	for id, p := range preparedByID {
		keep := false
		for i := range staged {
			if staged[i].ID == id && prepared[i].tmpPath != "" {
				keep = true

				break
			}
		}
		if !keep && p.tmpPath != "" {
			_ = os.Remove(p.tmpPath)
		}
	}

	res = sourceStageResult{
		staged:          staged,
		prepared:        prepared,
		requiresRestart: updated > 0,
		updated:         updated,
		warnings:        warnings,
	}

	return res
}

// shouldRefresh reports whether src should be downloaded.  force bypasses the
// update interval.  intervalHours of 0 disables non-forced refreshes, matching
// the filtering-rule list behaviour.
func shouldRefresh(src UpstreamDNSSourceYAML, intervalHours uint32, force bool) (ok bool) {
	if !src.Enabled {
		return false
	}
	if force {
		return true
	}
	if intervalHours == 0 {
		return false
	}
	if src.LastUpdated.IsZero() {
		return true
	}

	exp := src.LastUpdated.Add(time.Duration(intervalHours) * time.Hour)

	return !time.Now().Before(exp)
}

func (m *sourceManager) updateIntervalHours() (hours uint32) {
	if m.filter == nil {
		return 0
	}

	return m.filter.FiltersUpdateIntervalHours()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}

	return 0
}

func (m *sourceManager) all() (sources []UpstreamDNSSourceYAML) {
	sources = make([]UpstreamDNSSourceYAML, 0, len(m.conf.UpstreamDNSSources))
	for _, src := range m.conf.UpstreamDNSSources {
		sources = append(sources, src.clone())
	}

	return sources
}

// byURL returns the source with the given URL and whether it was found.
func (m *sourceManager) byURL(srcURL string) (src UpstreamDNSSourceYAML, ok bool) {
	idx := slices.IndexFunc(m.conf.UpstreamDNSSources, func(cur UpstreamDNSSourceYAML) bool {
		return cur.URL == srcURL
	})
	if idx < 0 {
		return UpstreamDNSSourceYAML{}, false
	}

	return m.conf.UpstreamDNSSources[idx].clone(), true
}

// ensureCaches downloads and commits enabled upstream sources whose cache
// files are missing.  Failures are recorded on the source as LastError and
// skipped so that DNS startup is not blocked by a single unreachable source.
func (m *sourceManager) ensureCaches(ctx context.Context) {
	if m.conf == nil || m.conf.UpstreamDNSFileName != "" {
		return
	}

	for i := range m.conf.UpstreamDNSSources {
		src := &m.conf.UpstreamDNSSources[i]
		if !src.Enabled {
			continue
		}

		m.migrateLegacyCache(src)

		cachePath := src.path(m.dataDir)
		_, err := os.Stat(cachePath)
		if err == nil {
			// Cache is present; clear stale load errors from previous boots.
			if strings.Contains(src.LastError, "cache does not exist") ||
				strings.Contains(src.LastError, "cache missing") {
				src.LastError = ""
			}

			continue
		}
		if !stderrors.Is(err, os.ErrNotExist) {
			src.LastError = err.Error()
			m.logger.WarnContext(
				ctx,
				"checking upstream source cache",
				"url", src.URL,
				slogutil.KeyError, err,
			)

			continue
		}

		m.logger.InfoContext(ctx, "upstream source cache missing, fetching", "url", src.URL)

		p, prepErr := m.prepare(ctx, src.clone())
		if prepErr != nil {
			src.LastError = prepErr.Error()
			m.logger.WarnContext(
				ctx,
				"fetching missing upstream source cache",
				"url", src.URL,
				slogutil.KeyError, prepErr,
			)

			continue
		}

		p.prevChecksum = src.checksum

		_, _, commitErr := m.commit(src, p)
		if commitErr != nil {
			_ = os.Remove(p.tmpPath)
			src.LastError = commitErr.Error()
			m.logger.WarnContext(
				ctx,
				"committing missing upstream source cache",
				"url", src.URL,
				slogutil.KeyError, commitErr,
			)
		}
	}
}
