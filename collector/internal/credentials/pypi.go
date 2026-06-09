package credentials

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/blast-radius/collector/internal/profile"
)

func collectPyPI(p profile.Profile) []CredentialItem {
	return parsePypirc(p.Username, filepath.Join(p.Path, ".pypirc"))
}

func parsePypirc(sourceUser, path string) []CredentialItem {
	sections := parseINIFile(path)
	if len(sections) == 0 {
		return nil
	}

	info, _ := os.Stat(path)
	var mtime string
	if info != nil {
		mtime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}

	// [distutils] lists the index-servers; all other sections are repositories
	var repoNames []string
	if dt, ok := sections["distutils"]; ok {
		for _, name := range parseDistutilsServers(dt["index-servers"]) {
			repoNames = append(repoNames, name)
		}
	}
	// If distutils is missing, treat every non-distutils section as a repo
	if len(repoNames) == 0 {
		for name := range sections {
			if name != "distutils" {
				repoNames = append(repoNames, name)
			}
		}
	}

	var items []CredentialItem
	for _, repo := range repoNames {
		fields, ok := sections[repo]
		if !ok {
			continue
		}
		password := fields["password"]
		if password == "" {
			continue
		}
		repoURL := fields["repository"]
		username := fields["username"]

		item := NewCredentialItem(sourceUser, "pypi_token", path, password)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"repository": repoURL,
			"username":   username,
		}
		items = append(items, item)
	}
	return items
}

func parseDistutilsServers(raw string) []string {
	var names []string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}
