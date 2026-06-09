package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/blast-radius/collector/internal/profile"
)

func collectAzure(p profile.Profile) []CredentialItem {
	azureDir := filepath.Join(p.Path, ".azure")

	var items []CredentialItem
	items = append(items, collectAzureAccessTokens(p.Username, azureDir)...)
	items = append(items, collectAzureMSALCache(p.Username, azureDir)...)
	return items
}

// accessTokensEntry is a partial decode of ~/.azure/accessTokens.json entries.
type accessTokensEntry struct {
	AccessToken  string `json:"accessToken"`
	TokenType    string `json:"tokenType"`
	ExpiresOn    string `json:"expiresOn"`
	UserID       string `json:"userId"`
	TenantID     string `json:"_clientId"` // field name varies by CLI version
	Tenant       string `json:"tenant"`
	Subscription string `json:"subscription"`
	IsMRRT       bool   `json:"isMRRT"`
}

func collectAzureAccessTokens(sourceUser, azureDir string) []CredentialItem {
	path := filepath.Join(azureDir, "accessTokens.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	info, _ := os.Stat(path)
	var mtime string
	if info != nil {
		mtime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}

	var entries []accessTokensEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}

	var items []CredentialItem
	for _, e := range entries {
		if e.AccessToken == "" {
			continue
		}
		tenantID := e.TenantID
		if tenantID == "" {
			tenantID = e.Tenant
		}

		item := NewCredentialItem(sourceUser, "azure_token", path, e.AccessToken)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"tenant_id":       tenantID,
			"subscription_id": e.Subscription,
			"account_type":    e.UserID,
			"token_type":      e.TokenType,
		}
		items = append(items, item)
	}
	return items
}

// msalCacheAccounts is a partial decode of ~/.azure/msal_token_cache.json
type msalCacheAccounts struct {
	Account map[string]struct {
		HomeAccountID string `json:"home_account_id"`
		Environment   string `json:"environment"`
		Realm         string `json:"realm"`
		Username      string `json:"username"`
		AccountType   string `json:"account_type"`
	} `json:"Account"`
	AccessToken map[string]struct {
		Secret        string `json:"secret"`
		TokenType     string `json:"token_type"`
		Realm         string `json:"realm"`
		HomeAccountID string `json:"home_account_id"`
	} `json:"AccessToken"`
}

func collectAzureMSALCache(sourceUser, azureDir string) []CredentialItem {
	path := filepath.Join(azureDir, "msal_token_cache.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	info, _ := os.Stat(path)
	var mtime string
	if info != nil {
		mtime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}

	var cache msalCacheAccounts
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}

	// Build account lookup by home_account_id
	type acctInfo struct {
		username    string
		accountType string
		realm       string
	}
	accts := map[string]acctInfo{}
	for _, a := range cache.Account {
		accts[a.HomeAccountID] = acctInfo{
			username:    a.Username,
			accountType: a.AccountType,
			realm:       a.Realm,
		}
	}

	var items []CredentialItem
	for _, tok := range cache.AccessToken {
		if tok.Secret == "" {
			continue
		}
		acct := accts[tok.HomeAccountID]
		item := NewCredentialItem(sourceUser, "azure_token", path, tok.Secret)
		item.FoundAt = mtime
		item.Context = map[string]any{
			"tenant_id":       tok.Realm,
			"subscription_id": "",
			"account_type":    acct.accountType,
			"token_type":      tok.TokenType,
		}
		items = append(items, item)
	}
	return items
}
