package configmgr

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// UpstreamDNSSource represents the on-disk upstream DNS source list.  The
// cache and the runtime status of a source are kept separately by the DNS
// server.
type UpstreamDNSSource struct {
	// Enabled indicates whether the source list is used.
	Enabled bool `yaml:"enabled"`

	// URL is the location of the source list, which can be a URL or an
	// absolute file path.
	URL string `yaml:"url"`

	// Name is the human-readable name of the source list.
	Name string `yaml:"name"`

	// ID is automatically assigned when the source is added.
	ID uint64 `yaml:"id"`
}

// type check
var _ validate.Interface = (*UpstreamDNSSource)(nil)

// Validate implements the [validate.Interface] interface for
// *UpstreamDNSSource.
func (s *UpstreamDNSSource) Validate() (err error) {
	if s == nil {
		return errors.ErrNoValue
	}

	// TODO(d.kolyshev):  Add more validations.

	return nil
}
