package vscode

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type VSCodeState struct {
	Extensions     []ExtensionInfo `json:"extensions"`
	StateDBSecrets []StateDBSecret `json:"state_db_secrets"`
	StorageFlags   []StorageFlag   `json:"storage_flags"`
}

type ExtensionInfo struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Publisher          string   `json:"publisher"`
	Version            string   `json:"version"`
	InstalledAt        string   `json:"installed_at"`
	ActivationEvents   []string `json:"activation_events"`
	Commands           []string `json:"commands"`
	IsUnknownPublisher bool     `json:"is_unknown_publisher"`
}

type StateDBSecret struct {
	Key           string `json:"key"`
	ValueRedacted string `json:"value_redacted"`
}

type StorageFlag struct {
	ExtensionID      string `json:"extension_id"`
	HasSecretStorage bool   `json:"has_secret_storage"`
}

// knownPublishers is a heuristic only. IsUnknownPublisher=true is metadata for
// the analyst, not a verdict — legitimate extensions exist outside this list.
var knownPublishers = map[string]bool{
	"microsoft": true, "ms-vscode": true, "ms-python": true, "ms-vscode-remote": true,
	"redhat": true, "github": true, "golang": true, "esbenp": true,
	"dbaeumer": true, "eamodio": true, "formulahendry": true, "ms-azuretools": true,
	"vscodevim": true, "ritwickdey": true, "pkief": true, "streetsidesoftware": true,
	"aaron-bond": true, "ms-toolsai": true, "ms-kubernetes-tools": true,
	"hashicorp": true, "rust-lang": true, "tamasfe": true, "yzhang": true,
	"ms-ceintl": true, "ms-edgedevtools": true, "ms-vscode-js-debug": true,
}

var secretKeyPatterns = []string{
	"token", "secret", "key", "auth", "credential", "password",
}

type vscodeDirs struct {
	extensions    string
	globalStorage string
}

func Collect() VSCodeState {
	var state VSCodeState
	for _, d := range vscodePaths() {
		state.Extensions = append(state.Extensions, collectExtensions(d.extensions)...)
		state.StateDBSecrets = append(state.StateDBSecrets, collectStateDB(filepath.Join(d.globalStorage, "state.vscdb"))...)
		state.StorageFlags = append(state.StorageFlags, scanExtensionStorage(d.globalStorage)...)
	}
	return state
}

func vscodePaths() []vscodeDirs {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var dirs []vscodeDirs
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata != "" {
			dirs = append(dirs,
				vscodeDirs{
					extensions:    filepath.Join(home, ".vscode", "extensions"),
					globalStorage: filepath.Join(appdata, "Code", "User", "globalStorage"),
				},
				vscodeDirs{
					extensions:    filepath.Join(home, ".vscode-insiders", "extensions"),
					globalStorage: filepath.Join(appdata, "Code - Insiders", "User", "globalStorage"),
				},
			)
		}
	case "darwin":
		base := filepath.Join(home, "Library", "Application Support")
		dirs = append(dirs,
			vscodeDirs{
				extensions:    filepath.Join(home, ".vscode", "extensions"),
				globalStorage: filepath.Join(base, "Code", "User", "globalStorage"),
			},
			vscodeDirs{
				extensions:    filepath.Join(home, ".vscode-insiders", "extensions"),
				globalStorage: filepath.Join(base, "Code - Insiders", "User", "globalStorage"),
			},
		)
	default:
		dirs = append(dirs, vscodeDirs{
			extensions:    filepath.Join(home, ".vscode", "extensions"),
			globalStorage: filepath.Join(home, ".config", "Code", "User", "globalStorage"),
		})
	}
	return dirs
}

func collectExtensions(extDir string) []ExtensionInfo {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return nil
	}

	var infos []ExtensionInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(extDir, e.Name(), "package.json"))
		if err != nil {
			continue
		}

		var pkg struct {
			Name             string   `json:"name"`
			Publisher        string   `json:"publisher"`
			Version          string   `json:"version"`
			ActivationEvents []string `json:"activationEvents"`
			Contributes      struct {
				Commands []struct {
					Command string `json:"command"`
				} `json:"commands"`
			} `json:"contributes"`
		}
		if err := json.Unmarshal(data, &pkg); err != nil {
			continue
		}

		var installedAt string
		if fi, err := e.Info(); err == nil {
			installedAt = fi.ModTime().UTC().Format(time.RFC3339)
		}

		var cmds []string
		for _, c := range pkg.Contributes.Commands {
			if c.Command != "" {
				cmds = append(cmds, c.Command)
			}
		}

		pub := strings.ToLower(strings.TrimSpace(pkg.Publisher))
		infos = append(infos, ExtensionInfo{
			ID:                 pub + "." + strings.ToLower(strings.TrimSpace(pkg.Name)),
			Name:               pkg.Name,
			Publisher:          pkg.Publisher,
			Version:            pkg.Version,
			InstalledAt:        installedAt,
			ActivationEvents:   pkg.ActivationEvents,
			Commands:           cmds,
			IsUnknownPublisher: !knownPublishers[pub],
		})
	}
	return infos
}

func collectStateDB(dbPath string) []StateDBSecret {
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}

	// immutable=1: bypass all locking so we can read without modifying
	// the database, even when VS Code holds it open.
	p := filepath.ToSlash(dbPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows absolute path: C:/... → /C:/...
	}
	dsn := "file://" + p + "?immutable=1"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blast-radius: vscode state.vscdb open: %v\n", err)
		return nil
	}
	defer db.Close()

	var clauses []string
	var args []any
	for _, pat := range secretKeyPatterns {
		clauses = append(clauses, "lower(key) LIKE ?")
		args = append(args, "%"+pat+"%")
	}
	query := "SELECT key, value FROM ItemTable WHERE " + strings.Join(clauses, " OR ")

	rows, err := db.Query(query, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blast-radius: vscode state.vscdb query: %v\n", err)
		return nil
	}
	defer rows.Close()

	var secrets []StateDBSecret
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		if v == "" {
			continue
		}
		secrets = append(secrets, StateDBSecret{Key: k, ValueRedacted: redactValue(v)})
	}
	return secrets
}

func scanExtensionStorage(globalStorage string) []StorageFlag {
	entries, err := os.ReadDir(globalStorage)
	if err != nil {
		return nil
	}

	var flags []StorageFlag
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		extPath := filepath.Join(globalStorage, e.Name())
		flag := StorageFlag{ExtensionID: e.Name()}

		if _, err := os.Stat(filepath.Join(extPath, "secrets")); err == nil {
			flag.HasSecretStorage = true
		}

		if !flag.HasSecretStorage {
			jsons, _ := filepath.Glob(filepath.Join(extPath, "*.json"))
			for _, jf := range jsons {
				if hasSecretJSONKeys(jf) {
					flag.HasSecretStorage = true
					break
				}
			}
		}

		flags = append(flags, flag)
	}
	return flags
}

func hasSecretJSONKeys(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}
	for k := range obj {
		lower := strings.ToLower(k)
		for _, pat := range secretKeyPatterns {
			if strings.Contains(lower, pat) {
				return true
			}
		}
	}
	return false
}

func redactValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}
