package credentials

import (
	"math"
	"os"
	"strings"
)

// sensitiveNamePatterns are matched case-insensitively against env var names.
var sensitiveNamePatterns = []string{
	"TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL", "API_KEY",
}

// excludedPrefixes avoids flagging well-known non-secret variables that
// happen to contain a matched substring (e.g. PATH → no; PRIVATEKEY → yes).
var excludedNames = map[string]bool{
	"PATH":            true,
	"PATHEXT":         true,
	"COMPUTERNAME":    true,
	"PROCESSOR_LEVEL": true,
}

func collectEnvVars() []CredentialItem {
	var items []CredentialItem
	seen := map[string]bool{}

	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" {
			continue
		}
		if excludedNames[strings.ToUpper(k)] {
			continue
		}

		upper := strings.ToUpper(k)
		nameMatch := false
		for _, pattern := range sensitiveNamePatterns {
			if strings.Contains(upper, pattern) {
				nameMatch = true
				break
			}
		}

		entropyMatch := len(v) > 20 && shannonEntropy(v) > 4.5

		if !nameMatch && !entropyMatch {
			continue
		}

		if seen[v] {
			continue
		}
		seen[v] = true

		item := NewCredentialItem("env_secret", "env:"+k, v)
		item.Context = map[string]any{
			"var_name": k,
		}
		items = append(items, item)
	}

	return items
}

// shannonEntropy computes the Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
