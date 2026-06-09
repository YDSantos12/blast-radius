package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blast-radius/collector/internal/credentials"
	"github.com/blast-radius/collector/internal/git"
	"github.com/blast-radius/collector/internal/profile"
	"github.com/blast-radius/collector/internal/propagation"
	"github.com/blast-radius/collector/internal/sysmon"
	"github.com/blast-radius/collector/internal/system"
	"github.com/blast-radius/collector/internal/vscode"
)

const (
	version       = "0.1.0"
	moduleTimeout = 120 * time.Second
)

type Meta struct {
	Hostname            string   `json:"hostname"`
	Username            string   `json:"username"`
	OS                  string   `json:"os"`
	OSVersion           string   `json:"os_version"`
	CollectedAt         string   `json:"collected_at"`
	CollectorVersion    string   `json:"collector_version"`
	CollectorHash       string   `json:"collector_hash"`
	IncidentWindowStart string   `json:"incident_window_start"`
	WindowDefaulted     bool     `json:"window_defaulted,omitempty"`
	TimedOutModules     []string `json:"timed_out_modules,omitempty"`
	ScannedProfiles     []string `json:"scanned_profiles,omitempty"`
}

type EnvironmentState struct {
	EnvVars         map[string]string       `json:"env_vars"`
	// EnvVarsSource distinguishes who produced the env_vars snapshot.
	// "current_user"  — normal execution, env vars belong to the running user.
	// "SYSTEM_process" — -scan-all-users, env vars are from the SYSTEM process,
	//                    NOT from the compromised user. Do not treat an empty
	//                    result as "user had no secrets in environment".
	EnvVarsSource   string                  `json:"env_vars_source"`
	RegistryRunKeys []system.RegistryRunKey `json:"registry_run_keys"`
	ScheduledTasks  []system.ScheduledTask  `json:"scheduled_tasks"`
}

type Collection struct {
	Meta         Meta                         `json:"meta"`
	Credentials  []credentials.CredentialItem `json:"credentials"`
	VSCode       vscode.VSCodeState           `json:"vscode"`
	Git          git.GitState                 `json:"git"`
	Propagation     propagation.PropagationState `json:"propagation"`
	SysmonAvailable bool                         `json:"sysmon_available"`
	SysmonEvents    []sysmon.SysmonEvent         `json:"sysmon_events"`
	Environment  EnvironmentState             `json:"environment"`
}

func main() {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	now := time.Now().UTC()

	defaultOut := fmt.Sprintf("collection-%s-%s.json",
		strings.ReplaceAll(hostname, ".", "-"),
		now.Format("20060102T150405Z"))

	var (
		flagOut          = flag.String("out", defaultOut, "output path for collection.json")
		flagWindow       = flag.String("window", "", "incident window start in ISO 8601 UTC (e.g. 2026-01-15T03:00:00Z)")
		flagOnline       = flag.Bool("resolve-online", false, "enable online authority resolution (requires GITHUB_TOKEN env var)")
		flagVerbose      = flag.Bool("verbose", false, "print progress to stderr")
		flagScanAllUsers = flag.Bool("scan-all-users", false, "scan all real user profiles on the host (requires elevated privileges)")
	)
	flag.Parse()

	fmt.Fprintf(os.Stderr, "BLAST-RADIUS collector v%s — read-only, no modifications made\n", version)

	incidentWindow, windowDefaulted := parseWindow(*flagWindow, now)

	log := func(format string, a ...any) {
		if *flagVerbose {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n",
				time.Now().UTC().Format("15:04:05"),
				fmt.Sprintf(format, a...))
		}
	}

	// sha256 of the running binary so analysts can verify the USB-delivered
	// binary against a published hash before trusting the collection.
	collectorHash := selfHash()

	// Build the list of profiles to scan.
	var profiles []profile.Profile
	if *flagScanAllUsers {
		profiles = profile.All()
		if len(profiles) == 0 {
			// Fall back to current user if enumeration failed.
			profiles = []profile.Profile{profile.Current()}
		}
		log("scan-all-users: found %d profiles: %s", len(profiles), joinUsernames(profiles))
	} else {
		profiles = []profile.Profile{profile.Current()}
	}

	var timedOut []string

	// ── Credentials ──────────────────────────────────────────────────────────
	// Timeout covers the full multi-profile scan, not each profile individually.
	// Per-profile timeouts would multiply total time by N; a shared budget
	// keeps worst-case runtime bounded at moduleTimeout regardless of profile count.
	log("credentials")
	allCreds, to := runWithTimeout(moduleTimeout, func() []credentials.CredentialItem {
		var all []credentials.CredentialItem
		for _, p := range profiles {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "blast-radius: panic in credentials for %s: %v\n", p.Username, r)
					}
				}()
				all = append(all, credentials.Collect(p)...)
			}()
		}
		return all
	})
	if to {
		timedOut = append(timedOut, "credentials")
		log("credentials: timed out, partial results included")
	}

	// Env vars are process-scoped. Collect once regardless of profile count.
	// When running as SYSTEM with -scan-all-users the result reflects SYSTEM's
	// environment, not the compromised user's — CollectEnvVars is called with
	// "SYSTEM_process" to make this visible in source_user on each item.
	envVarsSourceUser := profiles[0].Username
	envVarsSource := "current_user"
	if *flagScanAllUsers {
		envVarsSourceUser = "SYSTEM_process"
		envVarsSource = "SYSTEM_process"
	}
	allCreds = append(allCreds, credentials.CollectEnvVars(envVarsSourceUser)...)
	allCreds = deduplicateCredentials(allCreds)

	// ── Git ───────────────────────────────────────────────────────────────────
	log("git")
	var gitStates []git.GitState
	gitStates, to = runWithTimeout(moduleTimeout, func() []git.GitState {
		var all []git.GitState
		for _, p := range profiles {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "blast-radius: panic in git for %s: %v\n", p.Username, r)
					}
				}()
				all = append(all, git.Collect(p))
			}()
		}
		return all
	})
	if to {
		timedOut = append(timedOut, "git")
		log("git: timed out, partial results included")
	}
	mergedGit := mergeGitStates(gitStates)

	// ── VS Code ───────────────────────────────────────────────────────────────
	log("vscode")
	var vsStates []vscode.VSCodeState
	vsStates, to = runWithTimeout(moduleTimeout, func() []vscode.VSCodeState {
		var all []vscode.VSCodeState
		for _, p := range profiles {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "blast-radius: panic in vscode for %s: %v\n", p.Username, r)
					}
				}()
				all = append(all, vscode.Collect(p))
			}()
		}
		return all
	})
	if to {
		timedOut = append(timedOut, "vscode")
		log("vscode: timed out, partial results included")
	}
	mergedVSCode := mergeVSCodeStates(vsStates)

	// ── Propagation ───────────────────────────────────────────────────────────
	// repoPaths is the union of all profiles' discovered repos — workflow
	// injections may be in any profile's checkout.
	log("propagation")
	allRepoPaths := mergedGit.RepoPaths()
	propState, to := runWithTimeout(moduleTimeout, func() propagation.PropagationState {
		return propagation.Collect(incidentWindow, allRepoPaths, *flagOnline, os.Getenv("GITHUB_TOKEN"), profiles)
	})
	if to {
		timedOut = append(timedOut, "propagation")
		log("propagation: timed out, partial results included")
	}

	// ── System (process-scoped — unchanged by profile count) ─────────────────
	log("system")
	sysState, to := runWithTimeout(moduleTimeout, system.Collect)
	if to {
		timedOut = append(timedOut, "system")
		log("system: timed out, partial results included")
	}

	// ── Sysmon (system-wide event log — unchanged by profile count) ───────────
	log("sysmon")
	sysmonState, to := runWithTimeout(moduleTimeout, func() sysmon.SysmonState {
		return sysmon.Collect(incidentWindow)
	})
	if to {
		timedOut = append(timedOut, "sysmon")
		log("sysmon: timed out, partial results included")
	}

	// Guarantee sysmon_events is [] not null when Sysmon is absent or timed out.
	// null is valid JSON but breaks analyst tooling that expects an array.
	sysmonEvents := sysmonState.Events
	if sysmonEvents == nil {
		sysmonEvents = []sysmon.SysmonEvent{}
	}

	col := Collection{
		Meta:            buildMeta(hostname, now, incidentWindow, windowDefaulted, collectorHash, timedOut, profiles, *flagScanAllUsers),
		Credentials:     allCreds,
		VSCode:          mergedVSCode,
		Git:             mergedGit,
		Propagation:     propState,
		SysmonAvailable: sysmonState.Available,
		SysmonEvents:    sysmonEvents,
		Environment: EnvironmentState{
			EnvVars:         collectAllEnvVars(),
			EnvVarsSource:   envVarsSource,
			RegistryRunKeys: sysState.RegistryRunKeys,
			ScheduledTasks:  sysState.ScheduledTasks,
		},
	}

	outPath := *flagOut
	// SENSITIVE OUTPUT: collection.json contains all environment variables in
	// plaintext and credential metadata. Written with 0600 (owner-only) permissions
	// on this host. Handle as sensitive data during transfer — use an encrypted
	// channel and delete after analysis is complete.
	if err := writeAtomic(outPath, col); err != nil {
		fmt.Fprintf(os.Stderr, "blast-radius: write failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Collection complete. Output: %s. Transfer to analyst machine for analysis.\n", outPath)
	fmt.Fprintf(os.Stderr, "WARNING: collection.json contains sensitive data. Transfer via encrypted channel and delete after analysis.\n")
}

func parseWindow(s string, now time.Time) (time.Time, bool) {
	if s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blast-radius: invalid -window value %q: %v\n", s, err)
			os.Exit(1)
		}
		return t.UTC(), false
	}
	// Default to 24h ago. Noted in meta.window_defaulted so the analyst knows
	// this was not supplied and may not bracket the actual incident.
	return now.Add(-24 * time.Hour), true
}

func buildMeta(hostname string, now, window time.Time, defaulted bool, hash string, timedOut []string, profiles []profile.Profile, scanAllUsers bool) Meta {
	u, _ := user.Current()
	username := ""
	if u != nil {
		username = u.Username
	}

	var scannedProfiles []string
	if scanAllUsers {
		scannedProfiles = joinUsernameSlice(profiles)
	}

	return Meta{
		Hostname:            hostname,
		Username:            username,
		OS:                  runtime.GOOS,
		OSVersion:           osVersion(),
		CollectedAt:         now.Format(time.RFC3339),
		CollectorVersion:    version,
		CollectorHash:       hash,
		IncidentWindowStart: window.UTC().Format(time.RFC3339),
		WindowDefaulted:     defaulted,
		TimedOutModules:     timedOut,
		ScannedProfiles:     scannedProfiles,
	}
}

// selfHash computes sha256 of the running binary so the analyst can verify
// the USB-delivered binary against a published hash before trusting results.
func selfHash() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// Resolve symlinks — on some systems os.Executable returns one.
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	f, err := os.Open(exe)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func writeAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// collectAllEnvVars snapshots every environment variable. The credentials
// package separately extracts secret-looking values as CredentialItems; this
// gives the analyst the full picture for correlation.
func collectAllEnvVars() map[string]string {
	env := make(map[string]string)
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}

// deduplicateCredentials removes duplicate credentials by ValueHash.
// In multi-profile scans the same token may appear in multiple profiles
// (e.g., a shared .npmrc or a process env var read once per profile).
// The first occurrence is kept; SourceUser on the kept item reflects whichever
// profile was scanned first.
func deduplicateCredentials(items []credentials.CredentialItem) []credentials.CredentialItem {
	seen := map[string]bool{}
	result := make([]credentials.CredentialItem, 0, len(items))
	for _, item := range items {
		if !seen[item.ValueHash] {
			seen[item.ValueHash] = true
			result = append(result, item)
		}
	}
	return result
}

// mergeGitStates combines per-profile git states into one.
// GlobalConfig is taken from the first profile — in multi-profile mode the
// analyst should correlate per-user config via the scanned_profiles list.
func mergeGitStates(states []git.GitState) git.GitState {
	if len(states) == 0 {
		return git.GitState{}
	}
	merged := states[0]
	for _, s := range states[1:] {
		merged.Repos = append(merged.Repos, s.Repos...)
		merged.RunnerArtifacts = append(merged.RunnerArtifacts, s.RunnerArtifacts...)
	}
	return merged
}

// mergeVSCodeStates combines per-profile VS Code states into one.
func mergeVSCodeStates(states []vscode.VSCodeState) vscode.VSCodeState {
	var merged vscode.VSCodeState
	for _, s := range states {
		merged.Extensions = append(merged.Extensions, s.Extensions...)
		merged.StateDBSecrets = append(merged.StateDBSecrets, s.StateDBSecrets...)
		merged.StorageFlags = append(merged.StorageFlags, s.StorageFlags...)
	}
	return merged
}

func joinUsernames(profiles []profile.Profile) string {
	return strings.Join(joinUsernameSlice(profiles), ", ")
}

func joinUsernameSlice(profiles []profile.Profile) []string {
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Username
	}
	return names
}

// runWithTimeout runs fn in a goroutine and returns its result, or the zero
// value and true if d elapses first. The goroutine is not cancelled — it exits
// when the program terminates. Acceptable for a one-shot forensic binary.
func runWithTimeout[T any](d time.Duration, fn func() T) (T, bool) {
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	select {
	case v := <-ch:
		return v, false
	case <-time.After(d):
		var zero T
		return zero, true
	}
}
