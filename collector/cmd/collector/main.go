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
}

type EnvironmentState struct {
	EnvVars         map[string]string       `json:"env_vars"`
	RegistryRunKeys []system.RegistryRunKey `json:"registry_run_keys"`
	ScheduledTasks  []system.ScheduledTask  `json:"scheduled_tasks"`
}

type Collection struct {
	Meta         Meta                         `json:"meta"`
	Credentials  []credentials.CredentialItem `json:"credentials"`
	VSCode       vscode.VSCodeState           `json:"vscode"`
	Git          git.GitState                 `json:"git"`
	Propagation  propagation.PropagationState `json:"propagation"`
	SysmonEvents []sysmon.SysmonEvent         `json:"sysmon_events"`
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
		flagOut     = flag.String("out", defaultOut, "output path for collection.json")
		flagWindow  = flag.String("window", "", "incident window start in ISO 8601 UTC (e.g. 2026-01-15T03:00:00Z)")
		flagOnline  = flag.Bool("resolve-online", false, "enable online authority resolution (requires GITHUB_TOKEN env var)")
		flagVerbose = flag.Bool("verbose", false, "print progress to stderr")
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

	var timedOut []string

	log("credentials")
	creds, to := runWithTimeout(moduleTimeout, credentials.Collect)
	if to {
		timedOut = append(timedOut, "credentials")
		log("credentials: timed out, partial results included")
	}

	log("git")
	gitState, to := runWithTimeout(moduleTimeout, git.Collect)
	if to {
		timedOut = append(timedOut, "git")
		log("git: timed out, partial results included")
	}

	log("vscode")
	vsState, to := runWithTimeout(moduleTimeout, vscode.Collect)
	if to {
		timedOut = append(timedOut, "vscode")
		log("vscode: timed out, partial results included")
	}

	log("propagation")
	propState, to := runWithTimeout(moduleTimeout, func() propagation.PropagationState {
		return propagation.Collect(incidentWindow, gitState.RepoPaths(), *flagOnline, os.Getenv("GITHUB_TOKEN"))
	})
	if to {
		timedOut = append(timedOut, "propagation")
		log("propagation: timed out, partial results included")
	}

	log("system")
	sysState, to := runWithTimeout(moduleTimeout, system.Collect)
	if to {
		timedOut = append(timedOut, "system")
		log("system: timed out, partial results included")
	}

	log("sysmon")
	sysmonState, to := runWithTimeout(moduleTimeout, func() sysmon.SysmonState {
		return sysmon.Collect(incidentWindow)
	})
	if to {
		timedOut = append(timedOut, "sysmon")
		log("sysmon: timed out, partial results included")
	}

	col := Collection{
		Meta:         buildMeta(hostname, now, incidentWindow, windowDefaulted, collectorHash, timedOut),
		Credentials:  creds,
		VSCode:       vsState,
		Git:          gitState,
		Propagation:  propState,
		SysmonEvents: sysmonState.Events,
		Environment: EnvironmentState{
			EnvVars:         collectAllEnvVars(),
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

func buildMeta(hostname string, now, window time.Time, defaulted bool, hash string, timedOut []string) Meta {
	u, _ := user.Current()
	username := ""
	if u != nil {
		username = u.Username
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
