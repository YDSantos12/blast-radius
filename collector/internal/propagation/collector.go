package propagation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type PropagationState struct {
	NpmPublish          []NpmPublishLog  `json:"npm_publish"`
	SuspiciousRepos     []SuspiciousRepo `json:"suspicious_repos"`
	WorkflowInjections  []WorkflowInject `json:"workflow_injections"`
	RunnerRegistrations []RunnerReg      `json:"runner_registrations"`
	OnlineCheckDone     bool             `json:"online_check_done"`
}

type NpmPublishLog struct {
	LogFile string `json:"log_file"`
	LogTime string `json:"log_time"`
	Line    string `json:"line"`
}

type SuspiciousRepo struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	CreatedAt    string `json:"created_at"`
	HTMLURL      string `json:"html_url"`
	MatchPattern string `json:"match_pattern"`
}

type WorkflowInject struct {
	RepoPath   string `json:"repo_path"`
	File       string `json:"file"`
	MTime      string `json:"mtime"`
	InWindow   bool   `json:"in_window"`
	IsFlagged  bool   `json:"is_flagged"`
	FlagReason string `json:"flag_reason,omitempty"`
}

type RunnerReg struct {
	Path string `json:"path"`
	Note string `json:"note"`
}

var (
	// 16–20 lowercase alphanumeric characters — pattern used by Shai-Hulud for
	// exfil repos to avoid obvious naming while still being machine-generated.
	exfilNameRe    = regexp.MustCompile(`^[a-z0-9]{16,20}$`)
	exfilDescTerms = []string{"shai-hulud", "second coming", "sha1hulud"}
)

// Collect detects propagation evidence. repoPaths is from git.GitState.RepoPaths().
// If resolveOnline is true and githubToken is non-empty, the GitHub API is called
// to check for newly-created repositories matching exfil patterns.
func Collect(incidentWindowStart time.Time, repoPaths []string, resolveOnline bool, githubToken string) PropagationState {
	state := PropagationState{}
	state.NpmPublish = scanNpmPublishLogs(incidentWindowStart)
	state.WorkflowInjections = scanWorkflowInjections(incidentWindowStart, repoPaths)
	state.RunnerRegistrations = scanRunnerRegistrations()

	if resolveOnline && githubToken != "" {
		state.OnlineCheckDone = true
		repos, err := fetchGitHubRepos(githubToken, incidentWindowStart)
		if err != nil {
			fmt.Fprintf(os.Stderr, "blast-radius: github repo fetch: %v\n", err)
		} else {
			for _, r := range repos {
				if matched, reason := classifyExfilRepo(r); matched {
					state.SuspiciousRepos = append(state.SuspiciousRepos, SuspiciousRepo{
						Name:         r.Name,
						Description:  r.Description,
						CreatedAt:    r.CreatedAt,
						HTMLURL:      r.HTMLURL,
						MatchPattern: reason,
					})
				}
			}
		}
	}

	return state
}

func scanNpmPublishLogs(since time.Time) []NpmPublishLog {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(home, ".npm", "_logs"))
	if err != nil {
		return nil
	}

	var results []NpmPublishLog
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		logTime := parseNpmLogTime(e.Name())
		if !since.IsZero() && !logTime.IsZero() && logTime.Before(since) {
			continue
		}
		logPath := filepath.Join(home, ".npm", "_logs", e.Name())
		for _, line := range scanLogForPublish(logPath) {
			ts := ""
			if !logTime.IsZero() {
				ts = logTime.UTC().Format(time.RFC3339)
			}
			results = append(results, NpmPublishLog{LogFile: logPath, LogTime: ts, Line: line})
		}
	}
	return results
}

// parseNpmLogTime extracts the timestamp from a npm debug log filename.
// Format: 2024-03-15T12_34_56_789Z-debug-0.log
func parseNpmLogTime(filename string) time.Time {
	base := filepath.Base(filename)
	idx := strings.Index(base, "-debug-")
	if idx < 0 {
		return time.Time{}
	}
	raw := base[:idx]
	tIdx := strings.IndexByte(raw, 'T')
	if tIdx < 0 {
		return time.Time{}
	}
	timePart := strings.TrimSuffix(raw[tIdx+1:], "Z")
	segs := strings.SplitN(timePart, "_", 4) // ["12","34","56","789"]
	if len(segs) < 3 {
		return time.Time{}
	}
	iso := raw[:tIdx] + "T" + segs[0] + ":" + segs[1] + ":" + segs[2]
	if len(segs) == 4 {
		iso += "." + segs[3]
	}
	t, err := time.Parse(time.RFC3339Nano, iso+"Z")
	if err != nil {
		return time.Time{}
	}
	return t
}

func scanLogForPublish(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var hits []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		if strings.Contains(lower, "publish") && !strings.Contains(lower, "unpublish") {
			hits = append(hits, strings.TrimSpace(line))
		}
	}
	return hits
}

type githubRepoJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	HTMLURL     string `json:"html_url"`
}

func fetchGitHubRepos(token string, since time.Time) ([]githubRepoJSON, error) {
	req, err := http.NewRequest(http.MethodGet,
		"https://api.github.com/user/repos?sort=created&direction=desc&per_page=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}

	var repos []githubRepoJSON
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, err
	}

	if since.IsZero() {
		return repos, nil
	}

	var filtered []githubRepoJSON
	for _, r := range repos {
		t, err := time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil {
			// Include repos whose date can't be parsed — completeness over precision.
			filtered = append(filtered, r)
			continue
		}
		if !t.Before(since) {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

func classifyExfilRepo(r githubRepoJSON) (bool, string) {
	if exfilNameRe.MatchString(strings.ToLower(r.Name)) {
		return true, "random_name_pattern"
	}
	desc := strings.ToLower(r.Description)
	for _, term := range exfilDescTerms {
		if strings.Contains(desc, term) {
			return true, "suspicious_description:" + term
		}
	}
	return false, ""
}

func scanWorkflowInjections(since time.Time, repoPaths []string) []WorkflowInject {
	var results []WorkflowInject
	for _, repoPath := range repoPaths {
		entries, err := os.ReadDir(filepath.Join(repoPath, ".github", "workflows"))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			mtime := fi.ModTime().UTC()
			inWindow := !since.IsZero() && !mtime.Before(since)

			// discussion.yaml is the known Shai-Hulud 2.0 workflow injection artifact.
			flagged := strings.EqualFold(name, "discussion.yaml") || strings.EqualFold(name, "discussion.yml")
			reason := ""
			if flagged {
				reason = "known_shai_hulud_artifact"
			}

			results = append(results, WorkflowInject{
				RepoPath:   repoPath,
				File:       name,
				MTime:      mtime.Format(time.RFC3339),
				InWindow:   inWindow,
				IsFlagged:  flagged || inWindow,
				FlagReason: reason,
			})
		}
	}
	return results
}

func scanRunnerRegistrations() []RunnerReg {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var regs []RunnerReg
	for _, base := range []string{
		filepath.Join(home, ".actions-runner"),
		filepath.Join(home, "actions-runner"),
	} {
		data, err := os.ReadFile(filepath.Join(base, ".runner"))
		if err != nil {
			continue
		}
		note := "runner_registered"
		for _, marker := range []string{"SHA1HULUD", "Shai-Hulud", "Second Coming"} {
			if strings.Contains(string(data), marker) {
				note = "suspicious_runner:" + marker
				break
			}
		}
		regs = append(regs, RunnerReg{Path: filepath.Join(base, ".runner"), Note: note})
	}
	return regs
}
