package git

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blast-radius/collector/internal/profile"
)

type GitState struct {
	GlobalConfig    GlobalGitConfig  `json:"global_config"`
	Repos           []RepoInfo       `json:"repos"`
	RunnerArtifacts []RunnerArtifact `json:"runner_artifacts"`
}

type GlobalGitConfig struct {
	UserName         string   `json:"user_name"`
	UserEmail        string   `json:"user_email"`
	CredentialHelper string   `json:"credential_helper"`
	IncludeIfPaths   []string `json:"include_if_paths"`
}

type RepoInfo struct {
	Path             string         `json:"path"`
	RemoteURLs       []string       `json:"remote_urls"`
	CredentialHelper string         `json:"credential_helper"`
	NonDefaultHooks  []string       `json:"non_default_hooks"`
	ReflogEntries    []string       `json:"reflog_entries"`
	WorkflowFiles    []WorkflowFile `json:"workflow_files"`
}

type WorkflowFile struct {
	Name  string `json:"name"`
	MTime string `json:"mtime"`
}

type RunnerArtifact struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func Collect(p profile.Profile) GitState {
	cfg := collectGlobalConfig(p.Path)
	repos := discoverRepos(p.Path, 3)

	var repoInfos []RepoInfo
	for _, rp := range repos {
		repoInfos = append(repoInfos, collectRepoInfo(rp))
	}

	return GitState{
		GlobalConfig:    cfg,
		Repos:           repoInfos,
		RunnerArtifacts: collectRunnerArtifacts(p.Path),
	}
}

// RepoPaths extracts just the repo paths from a GitState. Used by the
// propagation collector to avoid re-running discovery.
func (s GitState) RepoPaths() []string {
	paths := make([]string, 0, len(s.Repos))
	for _, r := range s.Repos {
		paths = append(paths, r.Path)
	}
	return paths
}

func collectGlobalConfig(home string) GlobalGitConfig {
	sections := parseGitINI(filepath.Join(home, ".gitconfig"))
	var cfg GlobalGitConfig

	if u := sections["user"]; u != nil {
		cfg.UserName = u["name"]
		cfg.UserEmail = u["email"]
	}
	if c := sections["credential"]; c != nil {
		cfg.CredentialHelper = c["helper"]
	}
	for section, fields := range sections {
		if strings.HasPrefix(section, "includeIf ") {
			if p := fields["path"]; p != "" {
				cfg.IncludeIfPaths = append(cfg.IncludeIfPaths, expandHome(p, home))
			}
		}
	}
	return cfg
}

// parseGitINI parses a gitconfig-format file into map[section]map[key]value.
// Section names are kept verbatim (e.g. `remote "origin"`, `includeIf "gitdir:..."`).
func parseGitINI(path string) map[string]map[string]string {
	result := map[string]map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	var section string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if result[section] == nil {
				result[section] = map[string]string{}
			}
			continue
		}
		if section == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return result
}

// skipDirs are not traversed when discovering repos. They're either build
// artifacts that can't contain .git directories or caches so large that
// walking them is prohibitively slow.
var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".cache":       true,
	"__pycache__":  true,
	".npm":         true,
	".cargo":       true,
	".rustup":      true,
	".gradle":      true,
}

func discoverRepos(root string, maxDepth int) []string {
	var repos []string

	// Check if home itself is a repo before entering the recursive walk.
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		return append(repos, root)
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if skipDirs[name] || name == ".git" {
				continue
			}
			sub := filepath.Join(dir, name)
			if _, err := os.Stat(filepath.Join(sub, ".git")); err == nil {
				repos = append(repos, sub)
				// Do not recurse into a found repo.
				continue
			}
			if depth < maxDepth {
				walk(sub, depth+1)
			}
		}
	}
	walk(root, 0)
	return repos
}

func collectRepoInfo(repoPath string) RepoInfo {
	info := RepoInfo{Path: repoPath}

	sections := parseGitINI(filepath.Join(repoPath, ".git", "config"))
	for section, fields := range sections {
		if strings.HasPrefix(section, `remote "`) {
			if url := fields["url"]; url != "" {
				info.RemoteURLs = append(info.RemoteURLs, url)
			}
		}
		if section == "credential" {
			info.CredentialHelper = fields["helper"]
		}
	}

	info.NonDefaultHooks = collectHooks(repoPath)
	info.ReflogEntries = collectReflog(repoPath)
	info.WorkflowFiles = collectWorkflows(repoPath)
	return info
}

func collectHooks(repoPath string) []string {
	entries, err := os.ReadDir(filepath.Join(repoPath, ".git", "hooks"))
	if err != nil {
		return nil
	}

	var hooks []string
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		if runtime.GOOS != "windows" {
			fi, err := e.Info()
			if err != nil || fi.Mode()&0111 == 0 {
				continue
			}
		}
		hooks = append(hooks, e.Name())
	}
	return hooks
}

func collectReflog(repoPath string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "git", "-C", repoPath, "reflog", "--oneline", "-20").Output()
	if err != nil {
		return nil
	}

	var entries []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			entries = append(entries, line)
		}
	}
	return entries
}

func collectWorkflows(repoPath string) []WorkflowFile {
	entries, err := os.ReadDir(filepath.Join(repoPath, ".github", "workflows"))
	if err != nil {
		return nil
	}

	var files []WorkflowFile
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
		files = append(files, WorkflowFile{
			Name:  name,
			MTime: fi.ModTime().UTC().Format(time.RFC3339),
		})
	}
	return files
}

func collectRunnerArtifacts(home string) []RunnerArtifact {
	var artifacts []RunnerArtifact

	for _, base := range []string{
		filepath.Join(home, ".actions-runner"),
		filepath.Join(home, "actions-runner"),
	} {
		fi, err := os.Stat(base)
		if err != nil || !fi.IsDir() {
			continue
		}
		artifacts = append(artifacts, RunnerArtifact{Path: base, Type: "runner_dir"})

		runnerCfg := filepath.Join(base, ".runner")
		if data, err := os.ReadFile(runnerCfg); err == nil {
			artifacts = append(artifacts, RunnerArtifact{Path: runnerCfg, Type: "runner_config"})
			for _, marker := range []string{"SHA1HULUD", "Shai-Hulud", "Second Coming"} {
				if strings.Contains(string(data), marker) {
					artifacts = append(artifacts, RunnerArtifact{
						Path: runnerCfg,
						Type: "suspicious_runner_name:" + marker,
					})
				}
			}
		}

		diagDir := filepath.Join(base, "_diag")
		if entries, err := os.ReadDir(diagDir); err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "Runner_") {
					artifacts = append(artifacts, RunnerArtifact{
						Path: filepath.Join(diagDir, e.Name()),
						Type: "runner_log",
					})
				}
			}
		}
	}

	return artifacts
}

func expandHome(path, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}
