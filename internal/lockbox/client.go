// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/lockbox/client.go
package lockbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

const (
	// pageLimit caps a single Lockbox /secrets/sync request. The server
	// returns at most this many events; we then page using the response's
	// server_time as the next cursor.
	pageLimit = 1000
	// maxPages bounds how many pages a single DeltaSync invocation will
	// fetch, guarding against a server that fails to advance the cursor.
	maxPages = 100
)

// errUnauthorized signals a 401 from /secrets/sync — DeltaSync uses it as the
// trigger to refresh the JWT and retry the same page once.
var errUnauthorized = errors.New("delta sync: unauthorized")

// Client is a Lockbox HTTP client. Create via NewClient.
type Client struct {
	endpoint string
	auth     *Auth
	http     *http.Client
}

// NewClient creates a Client. auth must have LoadOrRegister called first.
func NewClient(endpoint string, auth *Auth) *Client {
	return &Client{
		endpoint: endpoint,
		auth:     auth,
		http:     newHTTPClient(),
	}
}

// DeltaSync fetches secrets modified after `since` (Unix timestamp in seconds).
// Pass since=0 for a full sync. Pages internally until the server returns a
// short page; returns the accumulated secrets, the latest server_time seen
// (suitable as the next `since`), and any error.
//
// JWTs from Lockbox are short-lived (~60s); when a page returns 401 we refresh
// the token and retry that page once. Errors abort pagination — partial
// results from earlier pages are discarded so the caller's cursor stays at
// the original value and the next tick re-fetches the whole delta (reconciles
// are idempotent).
func (c *Client) DeltaSync(ctx context.Context, since int64) ([]SecretWithMetadata, int64, error) {
	token, err := c.auth.GetToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("acquire token: %w", err)
	}

	var allSecrets []SecretWithMetadata
	cursor := since
	for range maxPages {
		page, serverTime, err := c.fetchPage(ctx, token, cursor)
		if errors.Is(err, errUnauthorized) {
			// Token expired mid-pagination. Refresh once and retry the page.
			token, err = c.auth.GetToken(ctx)
			if err != nil {
				return nil, 0, fmt.Errorf("refresh token: %w", err)
			}
			page, serverTime, err = c.fetchPage(ctx, token, cursor)
		}
		if err != nil {
			return nil, 0, err
		}
		allSecrets = append(allSecrets, page...)
		if len(page) < pageLimit {
			return allSecrets, serverTime, nil
		}
		cursor = serverTime
	}
	return nil, 0, fmt.Errorf("DeltaSync: exceeded %d pages; server cursor may have stalled", maxPages)
}

func (c *Client) fetchPage(ctx context.Context, token string, since int64) ([]SecretWithMetadata, int64, error) {
	url := c.endpoint + "/secrets/sync?limit=" + strconv.Itoa(pageLimit) + "&since=" + strconv.FormatInt(since, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("delta sync request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, 0, errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("delta sync: status %d", resp.StatusCode)
	}

	var delta DeltaSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&delta); err != nil {
		return nil, 0, fmt.Errorf("decode delta sync response: %w", err)
	}
	return delta.Secrets, delta.ServerTime, nil
}
