package credentials

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/blast-radius/collector/internal/profile"
)

func collectNPM(p profile.Profile) []CredentialItem {
	var items []CredentialItem
	seen := map[string]bool{}

	candidates, _ := findNpmrcFiles(p.Path)
	for _, path := range candidates {
		if seen[path] {
			continue
		}
		seen[path] = true
		items = append(items, parseNpmrc(p.Username, path)...)
	}

	return items
}

// findNpmrcFiles returns the home .npmrc plus any .npmrc up to 2 levels deep.
func findNpmrcFiles(home string) ([]string, error) {
	var found []string

	top := filepath.Join(home, ".npmrc")
	if _, err := os.Stat(top); err == nil {
		found = append(found, top)
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		return found, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		l1 := filepath.Join(home, e.Name())
		check := filepath.Join(l1, ".npmrc")
		if _, err := os.Stat(check); err == nil {
			found = append(found, check)
		}

		sub, _ := os.ReadDir(l1)
		for _, s := range sub {
			if !s.IsDir() {
				continue
			}
			check2 := filepath.Join(l1, s.Name(), ".npmrc")
			if _, err := os.Stat(check2); err == nil {
				found = append(found, check2)
			}
		}
	}
	return found, nil
}

func parseNpmrc(sourceUser, path string) []CredentialItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil
	}
	mtime := info.ModTime().UTC().Format("2006-01-02T15:04:05Z")

	var items []CredentialItem

	scanner := bufio.NewScanner(f)
	var fullContent strings.Builder
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		fullContent.WriteString(line + "\n")
		lines = append(lines, line)
	}

	hasPublishHint := strings.Contains(fullContent.String(), "publish-registry") ||
		strings.Contains(fullContent.String(), "publish_registry")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "_authToken") {
			continue
		}
		// //registry.npmjs.org/:_authToken=<token>
		// //<scope>:_authToken=<token>
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			continue
		}
		prefix := strings.TrimSpace(line[:eqIdx])
		token := strings.TrimSpace(line[eqIdx+1:])
		if token == "" {
			continue
		}

		registry, scope := parseNpmrcPrefix(prefix)

		item := NewCredentialItem(sourceUser, "npm_token", path, token)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"registry":           registry,
			"scope":              scope,
			"has_publish_access": hasPublishHint,
		}
		items = append(items, item)
	}

	return items
}

// parseNpmrcPrefix extracts registry URL and scope from a key like
// //registry.npmjs.org/:_authToken or //@scope:registry.tld/:_authToken
func parseNpmrcPrefix(prefix string) (registry, scope string) {
	// strip leading //
	s := strings.TrimPrefix(prefix, "//")
	// strip trailing /:_authToken or :_authToken
	s = strings.TrimSuffix(s, "/:_authToken")
	s = strings.TrimSuffix(s, ":_authToken")

	if strings.HasPrefix(s, "@") {
		// scoped: @scope:registry or @scope
		parts := strings.SplitN(s, ":", 2)
		scope = parts[0]
		if len(parts) == 2 {
			registry = parts[1]
		}
	} else {
		registry = s
	}
	return registry, scope
}
