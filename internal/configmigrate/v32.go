package configmigrate

import "context"

// migrateTo32 performs the following changes:
//
//	# BEFORE:
//	'schema_version': 31
//	# …
//
//	# AFTER:
//	'schema_version': 32
//	'filtering':
//	  'upstream_dns_files': []
//	# …
//
// This migration initializes the upstream_dns_files field in the filtering
// configuration. This field stores managed upstream DNS files that can be
// downloaded and updated similar to filter lists.
func (m *Migrator) migrateTo32(_ context.Context, diskConf yobj) (err error) {
	diskConf["schema_version"] = 32

	fltConf, ok, err := fieldVal[yobj](diskConf, "filtering")
	if !ok {
		if err != nil {
			return err
		}

		// If there's no filtering section, create one
		fltConf = yobj{}
		diskConf["filtering"] = fltConf
	}

	// Initialize upstream_dns_files as an empty array if it doesn't exist
	if _, ok := fltConf["upstream_dns_files"]; !ok {
		fltConf["upstream_dns_files"] = yarr{}
	}

	return nil
}
