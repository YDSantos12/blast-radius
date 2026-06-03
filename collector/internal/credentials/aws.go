package credentials

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func collectAWS() []CredentialItem {
	var items []CredentialItem
	items = append(items, collectAWSFiles()...)
	items = append(items, collectAWSEnv()...)
	return items
}

func collectAWSFiles() []CredentialItem {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	credPath := filepath.Join(home, ".aws", "credentials")
	cfgPath := filepath.Join(home, ".aws", "config")

	profiles := parseINIFile(credPath)
	configs := parseINIFile(cfgPath)

	ssoProfiles := extractSSOProfiles(configs)
	roleARNs := extractRoleARNs(configs)

	var items []CredentialItem

	for profile, fields := range profiles {
		keyID := fields["aws_access_key_id"]
		secret := fields["aws_secret_access_key"]
		sessionToken := fields["aws_session_token"]

		if keyID == "" && secret == "" {
			continue
		}

		// Use secret as the canonical value; fall back to key ID
		value := secret
		if value == "" {
			value = keyID
		}

		info, _ := os.Stat(credPath)
		var mtime string
		if info != nil {
			mtime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}

		item := NewCredentialItem("aws_key", credPath, value)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"profile":           profile,
			"key_id_prefix":     safePrefix(keyID, 8),
			"has_session_token": sessionToken != "",
			"source":            "file",
			"sso_configured":    ssoProfiles[profile],
			"role_arn":          roleARNs[profile],
		}
		items = append(items, item)
	}

	return items
}

func collectAWSEnv() []CredentialItem {
	keyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	session := os.Getenv("AWS_SESSION_TOKEN")
	profile := os.Getenv("AWS_PROFILE")

	if keyID == "" && secret == "" {
		return nil
	}

	value := secret
	if value == "" {
		value = keyID
	}

	item := NewCredentialItem("aws_key", "env:AWS_ACCESS_KEY_ID", value)
	item.Context = map[string]any{
		"profile":           profile,
		"key_id_prefix":     safePrefix(keyID, 8),
		"has_session_token": session != "",
		"source":            "env",
		"sso_configured":    false,
		"role_arn":          "",
	}
	return []CredentialItem{item}
}

// parseINIFile parses a simple INI file into map[section]map[key]value.
func parseINIFile(path string) map[string]map[string]string {
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
			section = strings.TrimSpace(line[1 : len(line)-1])
			// AWS config uses "profile <name>" headers
			section = strings.TrimPrefix(section, "profile ")
			result[section] = map[string]string{}
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

func extractSSOProfiles(configs map[string]map[string]string) map[string]bool {
	m := map[string]bool{}
	for profile, fields := range configs {
		if fields["sso_start_url"] != "" || fields["sso_account_id"] != "" {
			m[profile] = true
		}
	}
	return m
}

func extractRoleARNs(configs map[string]map[string]string) map[string]string {
	m := map[string]string{}
	for profile, fields := range configs {
		if arn := fields["role_arn"]; arn != "" {
			m[profile] = arn
		}
	}
	return m
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
