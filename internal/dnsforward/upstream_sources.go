package dnsforward

import (
	"bufio"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
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

const upstreamSourcesCacheDir = "filters"
const upstreamSourcesCachePrefix = "upstream-"

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
	checksum    uint64

	UpstreamDNSSource `yaml:",inline"`
}

// path returns the cache file path for source contents.
func (s *UpstreamDNSSourceYAML) path(dataDir string) string {
	return filepath.Join(
		dataDir,
		upstreamSourcesCacheDir,
		upstreamSourcesCachePrefix+strconv.FormatUint(s.ID, 10)+".txt",
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
	// filter is used to download upstream sources through the same path as
	// filtering-rule lists.
	filter *filtering.DNSFilter

	nextID uint64
}

func newSourceManager(conf *ServerConfig, l *slog.Logger, f *filtering.DNSFilter) *sourceManager {
	sm := &sourceManager{
		conf:   conf,
		logger: l,
		filter: f,
	}

	var maxID uint64
	if conf != nil {
		for i := range conf.UpstreamDNSSources {
			src := &conf.UpstreamDNSSources[i]
			if src.ID > maxID {
				maxID = src.ID
			}

			err := sm.loadMetadata(src)
			if err != nil {
				l.Warn("loading upstream source cache metadata", "url", src.URL, slogutil.KeyError, err)
			} else if src.LastUpdated.IsZero() {
				l.Debug("no cached metadata for upstream source, will fetch on next refresh", "url", src.URL)
			}
		}
	}

	sm.nextID = maxID + 1

	return sm
}

func (m *sourceManager) cacheDir() string {
	return filepath.Join(m.conf.DataDir, upstreamSourcesCacheDir)
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

	if m.filter == nil {
		return p, errors.New("dns filter is not initialized")
	}

	// Reuse the filtering-rule download path for local files and remote URLs.
	r, err := m.filter.Reader(src.URL)
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
	tr := io.TeeReader(r, writer)

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

func (m *sourceManager) commit(src *UpstreamDNSSourceYAML, p sourcePrepared) (updated bool, err error) {
	dst := src.path(m.conf.DataDir)

	if p.checksum == p.prevChecksum {
		_, statErr := os.Stat(dst)
		if statErr == nil {
			// 缓存存在且内容未变 → 跳过写入
			_ = os.Remove(p.tmpPath)

			return false, nil
		}

		if !stderrors.Is(statErr, os.ErrNotExist) {
			return false, fmt.Errorf("checking source cache: %w", statErr)
		}

		// 缓存文件不存在（ErrNotExist）→ 从 tmpPath 重建
		// 新源或缓存目录清理后均会进入此路径
	}

	err = os.Rename(p.tmpPath, dst)
	if err != nil {
		return false, fmt.Errorf("renaming source cache: %w", err)
	}

	src.ensureName(p.name)
	src.RulesCount = p.count
	src.checksum = p.checksum
	src.LastUpdated = p.lastUpdated

	return true, nil
}

func (m *sourceManager) cleanupPrepared(prepared []sourcePrepared) {
	for _, p := range prepared {
		if p.tmpPath == "" {
			continue
		}

		_ = os.Remove(p.tmpPath)
	}
}

func (m *sourceManager) loadMetadata(src *UpstreamDNSSourceYAML) (err error) {
	fileName := src.path(m.conf.DataDir)

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

func (m *sourceManager) applyPreparedLocked(staged []UpstreamDNSSourceYAML, prepared []sourcePrepared) (err error) {
	for i := range prepared {
		if prepared[i].tmpPath == "" {
			continue
		}

		if i >= len(staged) {
			continue
		}

		_, err = m.commit(&staged[i], prepared[i])
		if err != nil {
			m.cleanupPrepared(prepared[i:])

			return err
		}
		prepared[i].tmpPath = ""
	}

	removed := map[uint64]struct{}{}
	for _, cur := range m.conf.UpstreamDNSSources {
		if slices.ContainsFunc(staged, func(src UpstreamDNSSourceYAML) bool { return src.ID == cur.ID }) {
			continue
		}

		removed[cur.ID] = struct{}{}
	}

	for id := range removed {
		path := (&UpstreamDNSSourceYAML{UpstreamDNSSource: UpstreamDNSSource{ID: id}}).path(m.conf.DataDir)
		if rmErr := os.Rename(path, path+".old"); rmErr != nil && !stderrors.Is(rmErr, os.ErrNotExist) {
			m.logger.ErrorContext(context.Background(), "renaming source file", "path", path, slogutil.KeyError, rmErr)
		}
	}

	m.conf.UpstreamDNSSources = staged

	return nil
}

func (m *sourceManager) stageAdd(ctx context.Context, src UpstreamDNSSourceYAML) (res sourceStageResult, err error) {
	if slices.ContainsFunc(m.conf.UpstreamDNSSources, func(cur UpstreamDNSSourceYAML) bool { return cur.URL == src.URL }) {
		return res, errors.New("url already exists")
	}

	staged := m.cloneSources()
	prepared := make([]sourcePrepared, len(staged)+1)

	src.ID = m.nextID
	m.nextID++

	p, err := m.prepare(ctx, src)
	if err != nil {
		m.cleanupPrepared(prepared)

		return res, fmt.Errorf("preparing source: %w", err)
	}
	p.prevChecksum = src.checksum

	src.ensureName(p.name)
	src.RulesCount = p.count
	src.checksum = p.checksum
	src.LastUpdated = p.lastUpdated

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

func (m *sourceManager) stageSet(ctx context.Context, oldURL string, data UpstreamDNSSourceYAML) (res sourceStageResult, err error) {
	staged := m.cloneSources()
	idx := slices.IndexFunc(staged, func(src UpstreamDNSSourceYAML) bool { return src.URL == oldURL })
	if idx < 0 {
		return res, errors.New("url doesn't exist")
	}

	if oldURL != data.URL && slices.ContainsFunc(staged, func(src UpstreamDNSSourceYAML) bool { return src.URL == data.URL }) {
		return res, errors.New("url already exists")
	}

	src := staged[idx]
	prepared := make([]sourcePrepared, len(staged))

	metadataChanged := false
	semanticChanged := false
	needsPrepare := false
	prevEnabled := src.Enabled

	if src.Name != data.Name {
		src.Name = data.Name
		metadataChanged = true
	}

	if src.URL != data.URL {
		src.URL = data.URL
		src.clear()
		semanticChanged = true
		needsPrepare = data.Enabled
	}

	if src.Enabled != data.Enabled {
		src.Enabled = data.Enabled
		semanticChanged = true
		needsPrepare = data.Enabled
		if !data.Enabled {
			src.clear()
		}
	}

	hadContentChange := false
	if needsPrepare {
		p, prepErr := m.prepare(ctx, src.clone())
		if prepErr != nil {
			m.cleanupPrepared(prepared)

			return res, prepErr
		}
		p.prevChecksum = src.checksum

		hadContentChange = p.checksum != src.checksum
		src.ensureName(p.name)
		src.RulesCount = p.count
		src.checksum = p.checksum
		src.LastUpdated = p.lastUpdated
		prepared[idx] = p
	}

	staged[idx] = src

	res = sourceStageResult{
		staged:          staged,
		prepared:        prepared,
		requiresRestart: (semanticChanged && (prevEnabled || src.Enabled)) || hadContentChange,
		updated:         boolToInt(hadContentChange),
	}

	if !metadataChanged && !semanticChanged {
		res.staged = nil
	}

	return res, nil
}

func (m *sourceManager) stageRefresh(ctx context.Context) (res sourceStageResult, err error) {
	staged := m.cloneSources()
	prepared := make([]sourcePrepared, len(staged))
	warnings := []error{}
	updated := 0
	refreshed := 0

	for i := range staged {
		src := &staged[i]
		if !src.Enabled {
			continue
		}

		p, prepErr := m.prepare(ctx, src.clone())
		if prepErr != nil {
			warnings = append(warnings, fmt.Errorf("preparing source %q: %w", src.URL, prepErr))

			continue
		}
		p.prevChecksum = src.checksum

		refreshed++
		wasUpdated := p.checksum != src.checksum

		src.ensureName(p.name)
		src.RulesCount = p.count
		src.checksum = p.checksum
		prepared[i] = p

		if wasUpdated {
			src.LastUpdated = p.lastUpdated
			updated++
		}
	}

	if refreshed == 0 && len(warnings) > 0 {
		m.cleanupPrepared(prepared)

		return res, errors.Join(warnings...)
	}

	res = sourceStageResult{
		staged:          staged,
		prepared:        prepared,
		requiresRestart: updated > 0,
		updated:         updated,
		warnings:        warnings,
	}

	return res, nil
}

func (m *sourceManager) applyStaged(res sourceStageResult) (err error) {
	if res.staged == nil {
		return nil
	}

	return m.applyPreparedLocked(res.staged, res.prepared)
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
// files are missing.  Failures are logged and skipped so that DNS startup is
// not blocked by a single unreachable source.
func (m *sourceManager) ensureCaches(ctx context.Context) {
	if m.conf == nil || m.conf.UpstreamDNSFileName != "" {
		return
	}

	for i := range m.conf.UpstreamDNSSources {
		src := &m.conf.UpstreamDNSSources[i]
		if !src.Enabled {
			continue
		}

		cachePath := src.path(m.conf.DataDir)
		_, err := os.Stat(cachePath)
		if err == nil {
			continue
		}
		if !stderrors.Is(err, os.ErrNotExist) {
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
			m.logger.WarnContext(
				ctx,
				"fetching missing upstream source cache",
				"url", src.URL,
				slogutil.KeyError, prepErr,
			)

			continue
		}

		p.prevChecksum = src.checksum

		_, commitErr := m.commit(src, p)
		if commitErr != nil {
			_ = os.Remove(p.tmpPath)
			m.logger.WarnContext(
				ctx,
				"committing missing upstream source cache",
				"url", src.URL,
				slogutil.KeyError, commitErr,
			)
		}
	}
}
