package credentials

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func collectGitHub() []CredentialItem {
	var items []CredentialItem
	seen := map[string]bool{}

	add := func(item CredentialItem) {
		if seen[item.ValueHash] {
			return
		}
		seen[item.ValueHash] = true
		items = append(items, item)
	}

	for _, item := range collectGHCLI() {
		add(item)
	}
	for _, item := range collectGitCredentials() {
		add(item)
	}
	for _, item := range collectCredentialHelper() {
		add(item)
	}

	return items
}

func collectGHCLI() []CredentialItem {
	paths := ghCLIHostsPaths()
	var items []CredentialItem

	for _, p := range paths {
		entries, err := parseGHHostsYAML(p)
		if err != nil {
			continue
		}
		info, _ := os.Stat(p)
		var mtime string
		if info != nil {
			mtime = info.ModTime().UTC().Format(time.RFC3339)
		}
		for host, entry := range entries {
			if entry.token == "" {
				continue
			}
			item := NewCredentialItem("github_pat", p, entry.token)
			item.FoundAt = mtime
			item.Context = map[string]any{
				"source":       "gh_cli",
				"user":         entry.user,
				"token_prefix": classifyGitHubToken(entry.token),
				"host":         host,
			}
			items = append(items, item)
		}
	}
	return items
}

type ghHostEntry struct {
	token string
	user  string
}

// parseGHHostsYAML parses the gh CLI hosts.yml without an external YAML library.
//
// The format is a fixed two-level structure:
//   hostname:
//     oauth_token: <value>
//     user: <value>
//
// A full YAML parser would be more correct, but the format has been stable
// since gh CLI v1 and a line scanner avoids an external dependency.
func parseGHHostsYAML(path string) (map[string]ghHostEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := map[string]ghHostEntry{}
	var currentHost string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.TrimSpace(line) == "" {
			continue
		}

		// Top-level key: no leading whitespace, ends with ":"
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			currentHost = strings.TrimSuffix(strings.TrimSpace(line), ":")
			if _, ok := result[currentHost]; !ok {
				result[currentHost] = ghHostEntry{}
			}
			continue
		}

		if currentHost == "" {
			continue
		}

		trimmed := strings.TrimSpace(line)
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		entry := result[currentHost]
		switch k {
		case "oauth_token":
			entry.token = v
		case "user":
			entry.user = v
		}
		result[currentHost] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func ghCLIHostsPaths() []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "gh", "hosts.yml"))
	}
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "GitHub CLI", "hosts.yml"))
		}
	}
	return paths
}

func collectGitCredentials() []CredentialItem {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	p := filepath.Join(home, ".git-credentials")
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, _ := f.Stat()
	var mtime string
	if info != nil {
		mtime = info.ModTime().UTC().Format(time.RFC3339)
	}

	var items []CredentialItem
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "github.com") {
			continue
		}
		token, user := extractGitCredential(line)
		if token == "" {
			continue
		}
		item := NewCredentialItem("github_pat", p, token)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"source":       "git_credentials",
			"user":         user,
			"token_prefix": classifyGitHubToken(token),
		}
		items = append(items, item)
	}
	return items
}

func extractGitCredential(line string) (token, user string) {
	// https://user:token@host
	schemeEnd := strings.Index(line, "://")
	if schemeEnd < 0 {
		return "", ""
	}
	rest := line[schemeEnd+3:]
	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return "", ""
	}
	userInfo := rest[:atIdx]
	colonIdx := strings.Index(userInfo, ":")
	if colonIdx < 0 {
		return userInfo, ""
	}
	return userInfo[colonIdx+1:], userInfo[:colonIdx]
}

func collectCredentialHelper() []CredentialItem {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// git credential fill is the one exec the collector performs.
	// Strict 2s timeout prevents blocking on a hung credential helper.
	cmd := exec.CommandContext(ctx, "git", "credential", "fill")
	cmd.Stdin = bytes.NewBufferString("protocol=https\nhost=github.com\n\n")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var user, password string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if k, v, ok := strings.Cut(line, "="); ok {
			switch strings.TrimSpace(k) {
			case "username":
				user = strings.TrimSpace(v)
			case "password":
				password = strings.TrimSpace(v)
			}
		}
	}

	if password == "" {
		return nil
	}

	item := NewCredentialItem("github_pat", "credential_helper:github.com", password)
	item.Context = map[string]any{
		"source":       "credential_helper",
		"user":         user,
		"token_prefix": classifyGitHubToken(password),
	}
	return []CredentialItem{item}
}

func classifyGitHubToken(token string) string {
	for _, prefix := range []string{"ghp_", "gho_", "ghs_", "github_pat_"} {
		if strings.HasPrefix(token, prefix) {
			return fmt.Sprintf("%s...", prefix)
		}
	}
	return "unknown"
}
