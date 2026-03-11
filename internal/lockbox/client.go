// internal/lockbox/client.go
package lockbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

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
		http:     &http.Client{},
	}
}

// DeltaSync fetches secrets modified after `since` (Unix timestamp in seconds).
// Pass since=0 for a full sync. Returns secrets, the server_time to use as the
// next `since` value, and any error.
func (c *Client) DeltaSync(ctx context.Context, since int64) ([]SecretWithMetadata, int64, error) {
	token, err := c.auth.GetToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("acquire token: %w", err)
	}

	url := c.endpoint + "/secrets/sync?limit=1000&since=" + strconv.FormatInt(since, 10)
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
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("delta sync: status %d", resp.StatusCode)
	}

	var delta DeltaSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&delta); err != nil {
		return nil, 0, fmt.Errorf("decode delta sync response: %w", err)
	}
	return delta.Secrets, delta.ServerTime, nil
}
