package filtering

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// refreshUpstreamDNSFilesIntl checks upstream DNS files and updates them if necessary.
// If force is true, it ignores the file.LastUpdated field value.
// It returns the number of updated files and true if there was a network error.
func (d *DNSFilter) refreshUpstreamDNSFilesIntl(force bool) (int, bool) {
	ctx := context.TODO()

	updNum := 0
	d.logger.DebugContext(ctx, "starting upstream dns files update")
	defer func() {
		d.logger.DebugContext(ctx, "finished upstream dns files update", "updated", updNum)
	}()

	updNum, lists, toUpd, isNetErr := d.refreshFiltersArray(ctx, &d.conf.UpstreamDNSFiles, force)
	if isNetErr {
		return 0, true
	}

	if updNum == 0 {
		return 0, false
	}

	// Remove old file versions
	for i := range lists {
		if toUpd[i] {
			removeOldFilterFile(ctx, d.logger, lists[i].Path(d.conf.DataDir))
		}
	}

	return updNum, false
}

// tryRefreshUpstreamDNSFiles is like refreshUpstreamDNSFilesIntl, but backs down
// if the update is already going on.
func (d *DNSFilter) tryRefreshUpstreamDNSFiles(force bool) (updated int, isNetworkErr, ok bool) {
	if ok = d.refreshLock.TryLock(); !ok {
		return 0, false, false
	}
	defer d.refreshLock.Unlock()

	updated, isNetworkErr = d.refreshUpstreamDNSFilesIntl(force)

	return updated, isNetworkErr, ok
}

// GetUpstreamDNSFiles returns all upstream DNS files from all sources.
func (d *DNSFilter) GetUpstreamDNSFiles() (upstreams []string, err error) {
	d.conf.filtersMu.RLock()
	defer d.conf.filtersMu.RUnlock()

	for _, file := range d.conf.UpstreamDNSFiles {
		if !file.Enabled {
			continue
		}

		path := file.Path(d.conf.DataDir)

		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading upstream dns file %s: %w", path, err)
		}

		// Parse the file content - each line is an upstream server
		lines := splitLines(string(data))
		for _, line := range lines {
			line = trimComment(line)
			if line != "" {
				upstreams = append(upstreams, line)
			}
		}
	}

	return upstreams, nil
}

// splitLines splits text by newlines and returns non-empty lines.
func splitLines(text string) []string {
	var lines []string
	start := 0

	for i := 0; i < len(text); i++ {
		if text[i] == '\n' || text[i] == '\r' {
			if start < i {
				lines = append(lines, text[start:i])
			}
			start = i + 1
			// Skip \r\n
			if i+1 < len(text) && text[i] == '\r' && text[i+1] == '\n' {
				i++
				start = i + 1
			}
		}
	}

	if start < len(text) {
		lines = append(lines, text[start:])
	}

	return lines
}

// trimComment removes comments from a line (text after #).
func trimComment(line string) string {
	if idx := findCommentStart(line); idx >= 0 {
		line = line[:idx]
	}

	// Trim whitespace
	start := 0
	for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
		start++
	}

	end := len(line)
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}

	return line[start:end]
}

// findCommentStart finds the position of comment start (#).
func findCommentStart(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' {
			return i
		}
	}
	return -1
}

// upstreamDNSFileAdd adds a new upstream DNS file.
func (d *DNSFilter) upstreamDNSFileAdd(flt FilterYAML) (err error) {
	defer func() { err = errors.Annotate(err, "adding upstream dns file: %w") }()

	d.conf.filtersMu.Lock()
	defer d.conf.filtersMu.Unlock()

	// Check for duplicates
	if d.upstreamDNSFileExistsLocked(flt.URL) {
		return errFilterExists
	}

	d.conf.UpstreamDNSFiles = append(d.conf.UpstreamDNSFiles, flt)

	return nil
}

// upstreamDNSFileExistsLocked returns true if an upstream DNS file with the same
// URL exists. d.conf.filtersMu is expected to be locked.
func (d *DNSFilter) upstreamDNSFileExistsLocked(url string) bool {
	for _, f := range d.conf.UpstreamDNSFiles {
		if f.URL == url {
			return true
		}
	}

	return false
}

// upstreamDNSFileSetProperties searches for the particular upstream DNS file by url
// and sets the values of newFile to it, updating afterwards if needed.
func (d *DNSFilter) upstreamDNSFileSetProperties(
	fileURL string,
	newFile FilterYAML,
) (shouldRestart bool, err error) {
	d.conf.filtersMu.Lock()
	defer d.conf.filtersMu.Unlock()

	files := d.conf.UpstreamDNSFiles

	idx := -1
	for i := range files {
		if files[i].URL == fileURL {
			idx = i
			break
		}
	}

	if idx == -1 {
		return false, errFilterNotExist
	}

	flt := &files[idx]

	d.logger.DebugContext(
		context.TODO(),
		"updating upstream dns file",
		"name", newFile.Name,
		"url", newFile.URL,
		"enabled", newFile.Enabled,
		"file_url", flt.URL,
	)

	defer func(oldURL, oldName string, oldEnabled bool, oldUpdated time.Time, oldRulesCount int) {
		if err != nil {
			flt.URL = oldURL
			flt.Name = oldName
			flt.Enabled = oldEnabled
			flt.LastUpdated = oldUpdated
			flt.RulesCount = oldRulesCount
		}
	}(flt.URL, flt.Name, flt.Enabled, flt.LastUpdated, flt.RulesCount)

	flt.Name = newFile.Name

	if flt.URL != newFile.URL {
		if d.upstreamDNSFileExistsLocked(newFile.URL) {
			return false, errFilterExists
		}

		shouldRestart = true

		flt.URL = newFile.URL
		flt.LastUpdated = time.Time{}
		flt.unload()
	}

	if flt.Enabled != newFile.Enabled {
		flt.Enabled = newFile.Enabled
		shouldRestart = true
	}

	if !flt.Enabled {
		flt.unload()
		return shouldRestart, nil
	}

	if !shouldRestart {
		return false, nil
	}

	return d.update(flt)
}

// updateUpstreamDNSFilesInLoop is called periodically to check for updates.
func (d *DNSFilter) updateUpstreamDNSFilesInLoop() {
	ctx := context.TODO()

	if d.conf.FiltersUpdateIntervalHours == 0 {
		return
	}

	updated, isNetErr, ok := d.tryRefreshUpstreamDNSFiles(false)
	if !ok {
		d.logger.DebugContext(ctx, "upstream dns files update already in progress")
		return
	}

	if isNetErr {
		d.logger.WarnContext(ctx, "network error while updating upstream dns files")
		return
	}

	if updated > 0 {
		d.logger.InfoContext(ctx, "updated upstream dns files", "count", updated)
	}
}
