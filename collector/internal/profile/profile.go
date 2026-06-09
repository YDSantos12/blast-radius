package profile

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Profile represents a user account's home directory on the host.
type Profile struct {
	Path     string // absolute home directory path, e.g. C:\Users\jsmith
	Username string // login name, e.g. jsmith
}

// AppData returns the per-user roaming application data directory.
// Windows: Path\AppData\Roaming  (equivalent to %APPDATA% for this profile)
// Non-Windows: returns "" — callers should guard on GOOS before using.
//
// When the collector runs as SYSTEM, os.Getenv("APPDATA") resolves to the
// SYSTEM profile. This method derives the correct per-user path from Path,
// bypassing the process environment entirely.
func (p Profile) AppData() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(p.Path, "AppData", "Roaming")
	}
	return ""
}

// Current returns the profile of the user running the collector process.
func Current() Profile {
	u, err := user.Current()
	if err == nil && u.HomeDir != "" {
		return Profile{Path: u.HomeDir, Username: u.Username}
	}
	// Fallback — user.Current() can fail in cross-compiled binaries on some
	// platforms. Derive username from the directory name.
	if home, err := os.UserHomeDir(); err == nil {
		return Profile{Path: home, Username: filepath.Base(home)}
	}
	return Profile{}
}

// All enumerates real user profiles on the host.
//
// Windows: scans C:\Users\* (or %SystemDrive%\Users\*) and retains only
// directories that contain NTUSER.DAT. That file is created on first
// interactive login and absent from service accounts, junction points
// (Default User, All Users), and the Default template directory.
//
// Non-Windows: falls back to Current() — macOS Keychain multi-user scanning
// is not implemented in v0.1.
func All() []Profile {
	if runtime.GOOS != "windows" {
		if p := Current(); p.Path != "" {
			return []Profile{p}
		}
		return nil
	}

	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	// filepath.Join("C:", "Users") = "C:Users" (relative) on Windows.
	// Use string concatenation to ensure an absolute path.
	usersDir := systemDrive + `\Users`

	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil
	}

	// Named skip list is belt-and-suspenders: NTUSER.DAT filtering already
	// excludes these, but explicit names avoid following junction points,
	// which os.ReadDir may return as directories.
	skip := map[string]bool{
		"public":       true,
		"default":      true,
		"default user": true,
		"all users":    true,
	}

	var profiles []Profile
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if skip[strings.ToLower(e.Name())] {
			continue
		}
		profilePath := filepath.Join(usersDir, e.Name())
		// NTUSER.DAT is the authoritative marker: service accounts and
		// machine accounts either lack it or have it only under
		// C:\Windows\system32\config\systemprofile, which is not under
		// C:\Users and won't appear here.
		if _, err := os.Stat(filepath.Join(profilePath, "NTUSER.DAT")); err != nil {
			continue
		}
		profiles = append(profiles, Profile{
			Path:     profilePath,
			Username: e.Name(),
		})
	}
	return profiles
}
