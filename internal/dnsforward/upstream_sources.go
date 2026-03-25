package dnsforward

import (
	"context"
	"encoding/binary"
	"errors"
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
func (s *UpstreamDNSSourceYAML) path() string {
	return filepath.Join(
		"data",
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
	s.checksum = 0
}

func (s *UpstreamDNSSourceYAML) clone() (clone UpstreamDNSSourceYAML) {
	clone = *s

	return clone
}

// sourceReader returns an io.ReadCloser for the source URL or absolute file path.
func sourceReader(httpClient *http.Client, srcURL string) (r io.ReadCloser, err error) {
	if filepath.IsAbs(srcURL) {
		path := filepath.Clean(srcURL)

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

type sourcePrepared struct {
	tmpPath  string
	count    int
	checksum uint32
	name     string
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
		for _, src := range conf.UpstreamDNSSources {
			if src.ID > maxID {
				maxID = src.ID
			}
		}
	}

	sm.nextID = maxID + 1

	return sm
}

func (m *sourceManager) cacheDir() string {
	return filepath.Join("data", upstreamSourcesCacheDir)
}

func (m *sourceManager) sourceByURL(url string) (idx int, ok bool) {
	for i, src := range m.conf.UpstreamDNSSources {
		if src.URL == url {
			return i, true
		}
	}

	return -1, false
}

func validateSourceURL(urlStr string) (err error) {
	if filepath.IsAbs(urlStr) {
		urlStr = filepath.Clean(urlStr)
		_, err = os.Stat(urlStr)
		if err != nil {
			return err
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

func (m *sourceManager) prepare(ctx context.Context, src UpstreamDNSSourceYAML) (p sourcePrepared, err error) {
	err = os.MkdirAll(m.cacheDir(), aghos.DefaultPermDir)
	if err != nil {
		return p, fmt.Errorf("creating cache dir: %w", err)
	}

	r, err := sourceReader(m.httpClient, src.URL)
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
					}
					lineBuf.Reset()

					continue
				}

				lineBuf.WriteByte(b)
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}

			return p, fmt.Errorf("reading source: %w", readErr)
		}
	}

	if line := strings.TrimSpace(lineBuf.String()); line != "" && !aghnet.IsCommentOrEmpty(line) {
		lineCount++
	}

	title := ""
	if filepath.IsAbs(src.URL) {
		title = filepath.Base(src.URL)
	}

	v := h.Sum64()
	checksum := binary.LittleEndian.Uint32([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})

	_ = ctx

	p = sourcePrepared{
		tmpPath:  tmpFile.Name(),
		count:    lineCount,
		checksum: checksum,
		name:     title,
	}

	return p, nil
}

func (m *sourceManager) commit(src *UpstreamDNSSourceYAML, p sourcePrepared) (updated bool, err error) {
	dst := src.path()

	if p.checksum == src.checksum {
		_ = os.Remove(p.tmpPath)

		src.LastUpdated = time.Now()

		return false, nil
	}

	err = os.Rename(p.tmpPath, dst)
	if err != nil {
		return false, fmt.Errorf("renaming source cache: %w", err)
	}

	src.ensureName(p.name)
	src.RulesCount = p.count
	src.checksum = p.checksum
	src.LastUpdated = time.Now()

	return true, nil
}

func (m *sourceManager) add(ctx context.Context, src UpstreamDNSSourceYAML) (added UpstreamDNSSourceYAML, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	err = validateSourceURL(src.URL)
	if err != nil {
		return added, fmt.Errorf("checking source: %w", err)
	}

	if _, ok := m.sourceByURL(src.URL); ok {
		return added, errors.New("url already exists")
	}

	src.ID = m.nextID
	m.nextID++

	p, err := m.prepare(ctx, src)
	if err != nil {
		return added, fmt.Errorf("preparing source: %w", err)
	}

	_, err = m.commit(&src, p)
	if err != nil {
		return added, fmt.Errorf("committing source: %w", err)
	}

	m.conf.UpstreamDNSSources = append(m.conf.UpstreamDNSSources, src)

	return src.clone(), nil
}

func (m *sourceManager) remove(srcURL string) (removed UpstreamDNSSourceYAML, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx, ok := m.sourceByURL(srcURL)
	if !ok {
		return removed, errors.New("url doesn't exist")
	}

	removed = m.conf.UpstreamDNSSources[idx]
	m.conf.UpstreamDNSSources = slices.Delete(m.conf.UpstreamDNSSources, idx, idx+1)

	p := removed.path()
	if rmErr := os.Rename(p, p+".old"); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		m.logger.ErrorContext(context.Background(), "renaming source file", "path", p, slogutil.KeyError, rmErr)
	}

	return removed.clone(), nil
}

func (m *sourceManager) set(ctx context.Context, oldURL string, data UpstreamDNSSourceYAML) (restart bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx, ok := m.sourceByURL(oldURL)
	if !ok {
		return false, errors.New("url doesn't exist")
	}

	err = validateSourceURL(data.URL)
	if err != nil {
		return false, fmt.Errorf("checking source: %w", err)
	}

	if oldURL != data.URL {
		if _, dup := m.sourceByURL(data.URL); dup {
			return false, errors.New("url already exists")
		}
	}

	src := &m.conf.UpstreamDNSSources[idx]
	src.Name = data.Name

	if src.URL != data.URL {
		src.URL = data.URL
		src.clear()
		restart = true
	}

	if src.Enabled != data.Enabled {
		src.Enabled = data.Enabled
		restart = true
	}

	if !src.Enabled {
		src.clear()

		return restart, nil
	}

	if !restart {
		return false, nil
	}

	p, err := m.prepare(ctx, src.clone())
	if err != nil {
		return false, err
	}

	_, err = m.commit(src, p)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (m *sourceManager) refresh(ctx context.Context, force bool) (updated int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.conf.UpstreamDNSSources {
		src := &m.conf.UpstreamDNSSources[i]
		if !src.Enabled {
			continue
		}

		if !force && !src.LastUpdated.IsZero() {
			continue
		}

		p, prepErr := m.prepare(ctx, src.clone())
		if prepErr != nil {
			m.logger.ErrorContext(ctx, "refreshing upstream dns source", "url", src.URL, slogutil.KeyError, prepErr)

			continue
		}

		isUpdated, commitErr := m.commit(src, p)
		if commitErr != nil {
			m.logger.ErrorContext(ctx, "saving upstream dns source", "url", src.URL, slogutil.KeyError, commitErr)

			continue
		}

		if isUpdated {
			updated++
		}
	}

	return updated, nil
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
