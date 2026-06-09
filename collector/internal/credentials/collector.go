package credentials

import (
	"fmt"
	"os"

	"github.com/blast-radius/collector/internal/profile"
)

// Collect runs all profile-based sub-collectors against the given profile and
// returns every credential found. Env vars are process-scoped and are NOT
// collected here — use CollectEnvVars separately so main can call it once
// regardless of how many profiles are scanned.
func Collect(p profile.Profile) []CredentialItem {
	type runner struct {
		name string
		fn   func() []CredentialItem
	}

	runners := []runner{
		{"npm", func() []CredentialItem { return collectNPM(p) }},
		{"github", func() []CredentialItem { return collectGitHub(p) }},
		{"ssh", func() []CredentialItem { return collectSSH(p) }},
		{"aws", func() []CredentialItem { return collectAWS(p) }},
		{"azure", func() []CredentialItem { return collectAzure(p) }},
		{"pypi", func() []CredentialItem { return collectPyPI(p) }},
		{"docker", func() []CredentialItem { return collectDocker(p) }},
	}

	var all []CredentialItem
	for _, r := range runners {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					// Sub-collectors must not panic, but if one does we log
					// and continue rather than losing the entire collection.
					fmt.Fprintf(os.Stderr, "blast-radius: panic in %s collector for %s: %v\n", r.name, p.Username, rec)
				}
			}()
			items := r.fn()
			all = append(all, items...)
		}()
	}

	return all
}

// CollectEnvVars collects secret-looking environment variables from the running
// process. Env vars are process-scoped, not profile-scoped — there is no way to
// read another user's environment variables from disk.
//
// When the collector runs as SYSTEM with -scan-all-users, pass sourceUser =
// "SYSTEM_process" so the analyst knows these reflect SYSTEM's environment, not
// the compromised user's. Under normal single-user execution, pass the current
// user's username.
func CollectEnvVars(sourceUser string) []CredentialItem {
	return collectEnvVars(sourceUser)
}
