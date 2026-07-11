package filtering

import (
	"fmt"
	"path/filepath"
)

// PathMatchesAny returns true if filePath matches one of globs.  globs must be
// valid.  filePath must be absolute and clean.  If globs are empty,
// PathMatchesAny returns false.
//
// TODO(a.garipov): Move to golibs?
func PathMatchesAny(globs []string, filePath string) (ok bool) {
	return pathMatchesAny(globs, filePath)
}

// pathMatchesAny is the internal implementation of [PathMatchesAny].
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
