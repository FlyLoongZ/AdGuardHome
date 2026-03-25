package dnsforward

import (
	"context"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
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
	checksum    uint32

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

// sourceReader returns an io.ReadCloser for the source URL or absolute file path.
func sourceReader(httpClient *http.Client, srcURL string, safeFSPatterns []string) (r io.ReadCloser, err error) {
	if filepath.IsAbs(srcURL) {
		path := filepath.Clean(srcURL)
		if !pathMatchesAny(safeFSPatterns, path) {
			return nil, fmt.Errorf("path %q does not match safe patterns", path)
		}

		r, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening file: %w", err)
		}

		return r, nil
	}

	u, err := url.ParseRequestURI(srcURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	resp, err := httpClient.Get(srcURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("got status code %d, want %d", resp.StatusCode, http.StatusOK)
	}

	return resp.Body, nil
}

func pathMatchesAny(globs []string, filePath string) (ok bool) {
	if len(globs) == 0 {
		return false
	}

	clean, err := filepath.Abs(filePath)
	if err != nil {
		panic(fmt.Errorf("pathMatchesAny: %w", err))
	} else if clean != filePath {
		panic(fmt.Errorf("pathMatchesAny: filepath %q is not absolute", filePath))
	}

	for _, g := range globs {
		ok, err = filepath.Match(g, filePath)
		if err != nil {
			panic(fmt.Errorf("pathMatchesAny: bad pattern: %w", err))
		}

		if ok {
			return true
		}
	}

	return false
}

type sourcePrepared struct {
	tmpPath     string
	count       int
	checksum    uint32
	name        string
	lastUpdated time.Time
	upstreamLines []string
}

// sourceManager manages upstream DNS source lists and their cached contents.
type sourceManager struct {
	conf       *ServerConfig
	logger     *slog.Logger
	httpClient *http.Client

	mu     *sync.RWMutex
	nextID uint64
}

func newSourceManager(conf *ServerConfig, l *slog.Logger) *sourceManager {
	sm := &sourceManager{
		conf:       conf,
		logger:     l,
		httpClient: http.DefaultClient,
		mu:         &sync.RWMutex{},
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
			}
		}
	}

	sm.nextID = maxID + 1

	return sm
}

func (m *sourceManager) cacheDir() string {
	return filepath.Join(m.conf.DataDir, upstreamSourcesCacheDir)
}

func (m *sourceManager) sourceByURL(url string) (idx int, ok bool) {
	for i, src := range m.conf.UpstreamDNSSources {
		if src.URL == url {
			return i, true
		}
	}

	return -1, false
}

func validateSourceURL(urlStr string, safeFSPatterns []string) (err error) {
	if filepath.IsAbs(urlStr) {
		urlStr = filepath.Clean(urlStr)
		_, err = os.Stat(urlStr)
		if err != nil {
			return err
		}

		if !pathMatchesAny(safeFSPatterns, urlStr) {
			return fmt.Errorf("path %q does not match safe patterns", urlStr)
		}

		return nil
	}

	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	return nil
}

func (m *sourceManager) validateLines(lines []string) (err error) {
	if len(lines) == 0 {
		return nil
	}

	_, err = proxy.ParseUpstreamsConfig(lines, &upstream.Options{Logger: m.logger})
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

	r, err := sourceReader(m.httpClient, src.URL, m.conf.SafeFSPatterns)
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
	buf := make([]byte, 32*1024)

	lineBuf := strings.Builder{}
	lineCount := 0
	lines := []string{}
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = h.Write(chunk)

			_, err = tmpFile.Write(chunk)
			if err != nil {
				return p, fmt.Errorf("writing temp file: %w", err)
			}

			for _, b := range chunk {
				if b == '\n' {
					line := strings.TrimSpace(lineBuf.String())
					if line != "" && !aghnet.IsCommentOrEmpty(line) {
						lineCount++
						lines = append(lines, line)
					}
					lineBuf.Reset()

					continue
				}

				lineBuf.WriteByte(b)
			}
		}

		if readErr != nil {
			if stderrors.Is(readErr, io.EOF) {
				break
			}

			return p, fmt.Errorf("reading source: %w", readErr)
		}
	}

	if line := strings.TrimSpace(lineBuf.String()); line != "" && !aghnet.IsCommentOrEmpty(line) {
		lineCount++
		lines = append(lines, line)
	}

	err = m.validateLines(lines)
	if err != nil {
		return p, err
	}

	title := ""
	if filepath.IsAbs(src.URL) {
		title = filepath.Base(src.URL)
	}

	v := h.Sum64()
	checksum := binary.LittleEndian.Uint32([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})

	_ = ctx

	p = sourcePrepared{
		tmpPath:       tmpFile.Name(),
		count:         lineCount,
		checksum:      checksum,
		name:          title,
		lastUpdated:   time.Now(),
		upstreamLines: lines,
	}

	return p, nil
}

func (m *sourceManager) commit(src *UpstreamDNSSourceYAML, p sourcePrepared) (updated bool, err error) {
	dst := src.path(m.conf.DataDir)

	if p.checksum == src.checksum {
		_ = os.Remove(p.tmpPath)

		src.LastUpdated = p.lastUpdated

		return false, nil
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
	buf := make([]byte, 32*1024)
	lineBuf := strings.Builder{}
	lineCount := 0
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = h.Write(chunk)

			for _, b := range chunk {
				if b == '\n' {
					line := strings.TrimSpace(lineBuf.String())
					if line != "" && !aghnet.IsCommentOrEmpty(line) {
						lineCount++
					}
					lineBuf.Reset()

					continue
				}

				lineBuf.WriteByte(b)
			}
		}

		if readErr != nil {
			if stderrors.Is(readErr, io.EOF) {
				break
			}

			return fmt.Errorf("reading source file: %w", readErr)
		}
	}

	if line := strings.TrimSpace(lineBuf.String()); line != "" && !aghnet.IsCommentOrEmpty(line) {
		lineCount++
	}

	v := h.Sum64()
	src.RulesCount = lineCount
	src.checksum = binary.LittleEndian.Uint32([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
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

func (m *sourceManager) withStagedLocked(
	ctx context.Context,
	mutate func(sources []UpstreamDNSSourceYAML, nextID uint64) (staged []UpstreamDNSSourceYAML, prepared []sourcePrepared, newNextID uint64, out any, err error),
) (staged []UpstreamDNSSourceYAML, prepared []sourcePrepared, out any, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var newNextID uint64
	staged, prepared, newNextID, out, err = mutate(m.cloneSources(), m.nextID)
	if err != nil {
		m.cleanupPrepared(prepared)

		return nil, nil, nil, err
	}

	m.nextID = newNextID

	return staged, prepared, out, nil
}

func (m *sourceManager) applyLocked(staged []UpstreamDNSSourceYAML, prepared []sourcePrepared) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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

func (m *sourceManager) add(ctx context.Context, src UpstreamDNSSourceYAML) (staged []UpstreamDNSSourceYAML, prepared []sourcePrepared, added UpstreamDNSSourceYAML, err error) {
	out, prep, res, err := m.withStagedLocked(ctx, func(sources []UpstreamDNSSourceYAML, nextID uint64) ([]UpstreamDNSSourceYAML, []sourcePrepared, uint64, any, error) {
		err := validateSourceURL(src.URL, m.conf.SafeFSPatterns)
		if err != nil {
			return nil, nil, nextID, nil, fmt.Errorf("checking source: %w", err)
		}

		if slices.ContainsFunc(sources, func(cur UpstreamDNSSourceYAML) bool { return cur.URL == src.URL }) {
			return nil, nil, nextID, nil, errors.New("url already exists")
		}

		src.ID = nextID
		nextID++

		p, err := m.prepare(ctx, src)
		if err != nil {
			return nil, nil, nextID, nil, fmt.Errorf("preparing source: %w", err)
		}

		src.ensureName(p.name)
		src.RulesCount = p.count
		src.checksum = p.checksum
		src.LastUpdated = p.lastUpdated

		sources = append(sources, src)
		prepared := make([]sourcePrepared, len(sources))
		prepared[len(sources)-1] = p

		return sources, prepared, nextID, src.clone(), nil
	})
	if err != nil {
		return nil, nil, added, err
	}

	added = res.(UpstreamDNSSourceYAML)

	return out, prep, added, nil
}

func (m *sourceManager) remove(srcURL string) (staged []UpstreamDNSSourceYAML, removed UpstreamDNSSourceYAML, err error) {
	out, _, res, err := m.withStagedLocked(context.Background(), func(sources []UpstreamDNSSourceYAML, nextID uint64) ([]UpstreamDNSSourceYAML, []sourcePrepared, uint64, any, error) {
		idx := slices.IndexFunc(sources, func(src UpstreamDNSSourceYAML) bool { return src.URL == srcURL })
		if idx < 0 {
			return nil, nil, nextID, nil, errors.New("url doesn't exist")
		}

		removed := sources[idx].clone()
		sources = slices.Delete(sources, idx, idx+1)

		return sources, nil, nextID, removed, nil
	})
	if err != nil {
		return nil, removed, err
	}

	removed = res.(UpstreamDNSSourceYAML)

	return out, removed, nil
}

func (m *sourceManager) set(ctx context.Context, oldURL string, data UpstreamDNSSourceYAML) (staged []UpstreamDNSSourceYAML, prepared []sourcePrepared, changed bool, err error) {
	out, prep, res, err := m.withStagedLocked(ctx, func(sources []UpstreamDNSSourceYAML, nextID uint64) ([]UpstreamDNSSourceYAML, []sourcePrepared, uint64, any, error) {
		idx := slices.IndexFunc(sources, func(src UpstreamDNSSourceYAML) bool { return src.URL == oldURL })
		if idx < 0 {
			return nil, nil, nextID, nil, errors.New("url doesn't exist")
		}

		err := validateSourceURL(data.URL, m.conf.SafeFSPatterns)
		if err != nil {
			return nil, nil, nextID, nil, fmt.Errorf("checking source: %w", err)
		}

		if oldURL != data.URL && slices.ContainsFunc(sources, func(src UpstreamDNSSourceYAML) bool { return src.URL == data.URL }) {
			return nil, nil, nextID, nil, errors.New("url already exists")
		}

		src := sources[idx]
		changed := false

		if src.Name != data.Name {
			src.Name = data.Name
			changed = true
		}

		needsPrepare := false
		if src.URL != data.URL {
			src.URL = data.URL
			src.clear()
			changed = true
			needsPrepare = data.Enabled
		}

		if src.Enabled != data.Enabled {
			src.Enabled = data.Enabled
			changed = true
			needsPrepare = data.Enabled
			if !data.Enabled {
				src.clear()
			}
		}

		prepared := make([]sourcePrepared, len(sources))
		if needsPrepare {
			p, err := m.prepare(ctx, src.clone())
			if err != nil {
				return nil, nil, nextID, nil, err
			}

			src.ensureName(p.name)
			src.RulesCount = p.count
			src.checksum = p.checksum
			src.LastUpdated = p.lastUpdated
			prepared[idx] = p
		}

		sources[idx] = src

		return sources, prepared, nextID, changed, nil
	})
	if err != nil {
		return nil, nil, false, err
	}

	changed = res.(bool)

	return out, prep, changed, nil
}

func (m *sourceManager) refresh(ctx context.Context, force bool) (staged []UpstreamDNSSourceYAML, prepared []sourcePrepared, updated int, err error) {
	out, prep, res, err := m.withStagedLocked(ctx, func(sources []UpstreamDNSSourceYAML, nextID uint64) ([]UpstreamDNSSourceYAML, []sourcePrepared, uint64, any, error) {
		prepared := make([]sourcePrepared, len(sources))
		updated := 0

		for i := range sources {
			src := &sources[i]
			if !src.Enabled {
				continue
			}

			if !force && !src.LastUpdated.IsZero() {
				continue
			}

			p, prepErr := m.prepare(ctx, src.clone())
			if prepErr != nil {
				return nil, nil, nextID, nil, prepErr
			}

			wasUpdated := p.checksum != src.checksum

			src.ensureName(p.name)
			src.RulesCount = p.count
			src.checksum = p.checksum
			src.LastUpdated = p.lastUpdated
			prepared[i] = p

			if wasUpdated {
				updated++
			}
		}

		return sources, prepared, nextID, updated, nil
	})
	if err != nil {
		return nil, nil, 0, err
	}

	updated = res.(int)

	return out, prep, updated, nil
}

func (m *sourceManager) apply(staged []UpstreamDNSSourceYAML, prepared []sourcePrepared) (err error) {
	return m.applyLocked(staged, prepared)
}

func (m *sourceManager) all() (sources []UpstreamDNSSourceYAML) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources = make([]UpstreamDNSSourceYAML, 0, len(m.conf.UpstreamDNSSources))
	for _, src := range m.conf.UpstreamDNSSources {
		sources = append(sources, src.clone())
	}

	return sources
}
