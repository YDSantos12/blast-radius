package credentials

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

func collectSSH() []CredentialItem {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	sshDir := filepath.Join(home, ".ssh")

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}

	hostMap := parseSSHConfig(filepath.Join(sshDir, "config"))
	knownHosts := sampleKnownHosts(filepath.Join(sshDir, "known_hosts"))

	var items []CredentialItem
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(sshDir, e.Name())
		keyType, encrypted, ok := inspectSSHKey(p)
		if !ok {
			continue
		}

		info, _ := e.Info()
		var mtime string
		if info != nil {
			mtime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}

		// use the filename as the value for hashing/redaction since
		// private key material itself should never be read into memory
		item := NewCredentialItem("ssh_key", p, e.Name())
		item.FoundAt = mtime
		item.Context = map[string]any{
			"key_type":          keyType,
			"has_passphrase":    encrypted,
			"configured_hosts":  hostMap[e.Name()],
			"known_hosts_sample": knownHosts,
		}
		items = append(items, item)
	}
	return items
}

// inspectSSHKey reads just enough of the file to identify it as an SSH
// private key and determine whether it is passphrase-protected.
// It never loads the key into a crypto parser — we only scan headers.
func inspectSSHKey(path string) (keyType string, encrypted bool, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, false
	}
	defer f.Close()

	// Read up to 4 KB — enough for the PEM header and proc-type line
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	content := string(buf[:n])

	if !strings.Contains(content, "-----BEGIN") || !strings.Contains(content, "PRIVATE KEY-----") {
		return "", false, false
	}

	keyType = classifyKeyType(content)

	// OpenSSH format signals encryption with "aes" in the header block.
	// Legacy PEM format signals it with Proc-Type: 4,ENCRYPTED.
	encrypted = strings.Contains(content, "ENCRYPTED") ||
		strings.Contains(content, "aes256-ctr") ||
		strings.Contains(content, "aes256-cbc") ||
		strings.Contains(content, "aes128-ctr")

	return keyType, encrypted, true
}

func classifyKeyType(content string) string {
	switch {
	case strings.Contains(content, "RSA PRIVATE KEY") || strings.Contains(content, "-----BEGIN RSA"):
		return "RSA"
	case strings.Contains(content, "EC PRIVATE KEY") || strings.Contains(content, "-----BEGIN EC"):
		return "ECDSA"
	case strings.Contains(content, "OPENSSH PRIVATE KEY"):
		// OpenSSH format is used for both ED25519 and newer RSA keys;
		// we can distinguish by looking at the key body but that requires
		// base64 decoding. Returning OPENSSH is accurate enough for triage.
		if strings.Contains(content, "ed25519") {
			return "ED25519"
		}
		return "OPENSSH"
	default:
		return "unknown"
	}
}

// parseSSHConfig returns a map of private key filename → []hosts it is
// configured for. Only IdentityFile directives are parsed.
func parseSSHConfig(path string) map[string][]string {
	result := map[string][]string{}
	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	var currentHosts []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host ") {
			currentHosts = strings.Fields(line)[1:]
			continue
		}
		if strings.HasPrefix(lower, "identityfile ") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			keyPath := expandHome(fields[1])
			keyFile := filepath.Base(keyPath)
			result[keyFile] = append(result[keyFile], currentHosts...)
		}
	}
	return result
}

func sampleKnownHosts(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var hosts []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// first field is hostname(s), possibly hashed
		hostField := strings.Fields(line)[0]
		// hashed entries start with |1| — include as-is, not useful but present
		for _, h := range strings.Split(hostField, ",") {
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
		if len(hosts) >= 50 {
			break
		}
	}
	return hosts
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}
