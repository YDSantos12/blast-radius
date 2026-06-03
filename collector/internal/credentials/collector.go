package credentials

import (
	"fmt"
	"os"
)

// Collect runs all sub-collectors and returns every credential found.
// Each sub-collector is responsible for its own error handling; a failure
// in one must not suppress results from others.
func Collect() []CredentialItem {
	type runner struct {
		name string
		fn   func() []CredentialItem
	}

	runners := []runner{
		{"npm", collectNPM},
		{"github", collectGitHub},
		{"ssh", collectSSH},
		{"aws", collectAWS},
		{"azure", collectAzure},
		{"pypi", collectPyPI},
		{"docker", collectDocker},
		{"envvars", collectEnvVars},
	}

	var all []CredentialItem
	for _, r := range runners {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					// Sub-collectors must not panic, but if one does we log
					// and continue rather than losing the entire collection.
					fmt.Fprintf(os.Stderr, "blast-radius: panic in %s collector: %v\n", r.name, rec)
				}
			}()
			items := r.fn()
			all = append(all, items...)
		}()
	}

	return all
}
