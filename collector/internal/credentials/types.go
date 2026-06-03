package credentials

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

type CredentialItem struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Path          string         `json:"path"`
	ValueRedacted string         `json:"value_redacted"`
	ValueHash     string         `json:"value_hash"`
	FoundAt       string         `json:"found_at"`
	Context       map[string]any `json:"context"`
	Authority     map[string]any `json:"authority"`
	ExposureTier  string         `json:"exposure_tier"`
}

func NewCredentialItem(credType, path, rawValue string) CredentialItem {
	idHash := sha256.Sum256([]byte(credType + path))
	valHash := sha256.Sum256([]byte(rawValue))

	return CredentialItem{
		ID:            fmt.Sprintf("%x", idHash),
		Type:          credType,
		Path:          path,
		ValueRedacted: redact(rawValue),
		ValueHash:     fmt.Sprintf("%x", valHash),
		FoundAt:       time.Now().UTC().Format(time.RFC3339),
		Context:       map[string]any{},
		Authority:     map[string]any{},
		ExposureTier:  "",
	}
}

// redact masks all but the first 4 and last 4 characters.
// Short values (< 8 chars) are fully masked — revealing even a fragment
// of a short secret is worse than revealing nothing.
func redact(value string) string {
	v := strings.TrimSpace(value)
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}
