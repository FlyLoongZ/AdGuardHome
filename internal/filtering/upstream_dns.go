package filtering

import (
	"context"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// refreshUpstreamDNSFilesIntl checks upstream DNS files and updates them if necessary.
// If force is true, it ignores the file.LastUpdated field value.
// It returns the number of updated files and true if there was a network error.
func (d *DNSFilter) refreshUpstreamDNSFilesIntl(ctx context.Context, force bool) (int, bool) {
	updNum := 0
	d.logger.DebugContext(ctx, "starting upstream dns files update")
	defer func() {
		d.logger.DebugContext(ctx, "finished upstream dns files update", "updated", updNum)
	}()

	updNum, lists, toUpd, isNetErr := d.refreshFiltersArray(ctx, &d.conf.UpstreamDNSFiles, force)
	if isNetErr {
		d.logger.ErrorContext(ctx, "network error during upstream dns files update")
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
