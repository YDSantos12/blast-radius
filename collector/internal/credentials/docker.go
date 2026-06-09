package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/blast-radius/collector/internal/profile"
)

func collectDocker(p profile.Profile) []CredentialItem {
	return parseDockerConfig(p.Username, filepath.Join(p.Path, ".docker", "config.json"))
}

type dockerConfig struct {
	Auths     map[string]dockerAuth `json:"auths"`
	CredStore string                `json:"credsStore"`
}

type dockerAuth struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func parseDockerConfig(sourceUser, path string) []CredentialItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	info, _ := os.Stat(path)
	var mtime string
	if info != nil {
		mtime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}

	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}

	registries := make([]string, 0, len(cfg.Auths))
	for registry := range cfg.Auths {
		registries = append(registries, registry)
	}

	// When credsStore is set, passwords are in the OS keychain, not in this
	// file — auth entries will be empty. We still record the registries so
	// the analyst knows which registries have stored credentials.
	if cfg.CredStore != "" {
		item := NewCredentialItem(sourceUser, "docker_credential", path, cfg.CredStore)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"registries": registries,
			"cred_store": cfg.CredStore,
		}
		return []CredentialItem{item}
	}

	var items []CredentialItem
	for registry, auth := range cfg.Auths {
		// auth.Auth is base64(user:password); use it as the credential value
		value := auth.Auth
		if value == "" {
			value = auth.Password
		}
		if value == "" {
			continue
		}
		item := NewCredentialItem(sourceUser, "docker_credential", path, value)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"registries": []string{registry},
			"cred_store": "",
		}
		items = append(items, item)
	}
	return items
}
