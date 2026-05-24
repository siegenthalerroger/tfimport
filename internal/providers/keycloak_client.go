package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KeycloakObject is a minimal view of a Keycloak admin API object: its
// server-generated GUID (ID) and the natural-key value used to match it
// (clientId, username, name or alias depending on the resource).
type KeycloakObject struct {
	ID    string
	Match string
}

// KeycloakClient exposes the read-only lookups the custom resolvers need to
// translate a resource's natural key into its server-generated GUID. It is an
// interface so the resolvers can be unit-tested with a fake implementation.
type KeycloakClient interface {
	ListClients(ctx context.Context, realm, clientID string) ([]KeycloakObject, error)
	ListUsers(ctx context.Context, realm, username string) ([]KeycloakObject, error)
	ListClientScopes(ctx context.Context, realm string) ([]KeycloakObject, error)
	ListRealmRoles(ctx context.Context, realm string) ([]KeycloakObject, error)
	ListClientRoles(ctx context.Context, realm, clientGUID string) ([]KeycloakObject, error)
	ListTopLevelGroups(ctx context.Context, realm string) ([]KeycloakObject, error)
	ListAuthenticationFlows(ctx context.Context, realm string) ([]KeycloakObject, error)
	ListUserFederations(ctx context.Context, realm string) ([]KeycloakObject, error)
}

// GetKeycloakClient lazily constructs a Keycloak admin client from the same
// environment variables used by the Terraform Keycloak provider. It returns nil
// (and the resolvers fall back to "") when KEYCLOAK_URL is unset or no usable
// credentials are configured, so the tool degrades gracefully without Keycloak.
func (p *ProviderContext) GetKeycloakClient() KeycloakClient {
	p.keycloakOnce.Do(func() {
		if c := newKeycloakHTTPClientFromEnv(); c != nil {
			p.keycloakClient = c
		}
	})
	return p.keycloakClient
}

// newKeycloakHTTPClientFromEnv builds a client from the KEYCLOAK_* environment
// variables, or returns nil when the URL or credentials are absent.
func newKeycloakHTTPClientFromEnv() *keycloakHTTPClient {
	baseURL := strings.TrimRight(os.Getenv("KEYCLOAK_URL"), "/")
	if baseURL == "" {
		log.Printf("Keycloak: KEYCLOAK_URL not set, skipping API-based ID resolution")
		return nil
	}

	basePath := os.Getenv("KEYCLOAK_BASE_PATH")
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	basePath = strings.TrimRight(basePath, "/")

	adminURL := strings.TrimRight(os.Getenv("KEYCLOAK_ADMIN_URL"), "/")
	if adminURL == "" {
		adminURL = baseURL
	}

	authRealm := os.Getenv("KEYCLOAK_REALM")
	if authRealm == "" {
		authRealm = "master"
	}

	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	username := os.Getenv("KEYCLOAK_USER")
	if clientID == "" && username != "" {
		clientID = "admin-cli"
	}

	c := &keycloakHTTPClient{
		tokenURL:     baseURL + basePath + "/realms/" + url.PathEscape(authRealm) + "/protocol/openid-connect/token",
		adminBase:    adminURL + basePath + "/admin/realms/",
		clientID:     clientID,
		clientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		username:     username,
		password:     os.Getenv("KEYCLOAK_PASSWORD"),
		staticToken:  os.Getenv("KEYCLOAK_ACCESS_TOKEN"),
		httpClient:   &http.Client{Timeout: keycloakTimeout()},
	}

	switch {
	case c.staticToken != "":
	case c.username != "" && c.password != "": // password grant
	case c.clientSecret != "" && c.clientID != "": // client_credentials grant
	default:
		log.Printf("Keycloak: no usable credentials (set KEYCLOAK_ACCESS_TOKEN, KEYCLOAK_CLIENT_ID+KEYCLOAK_CLIENT_SECRET, or KEYCLOAK_USER+KEYCLOAK_PASSWORD), skipping API-based ID resolution")
		return nil
	}

	return c
}

func keycloakTimeout() time.Duration {
	if v := os.Getenv("KEYCLOAK_CLIENT_TIMEOUT"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 15 * time.Second
}

type keycloakHTTPClient struct {
	tokenURL     string
	adminBase    string
	clientID     string
	clientSecret string
	username     string
	password     string
	staticToken  string
	httpClient   *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func (c *keycloakHTTPClient) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.staticToken != "" {
		return c.staticToken, nil
	}
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	if c.username != "" && c.password != "" {
		form.Set("grant_type", "password")
		form.Set("username", c.username)
		form.Set("password", c.password)
		if c.clientSecret != "" {
			form.Set("client_secret", c.clientSecret)
		}
	} else {
		form.Set("grant_type", "client_credentials")
		form.Set("client_secret", c.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("keycloak token request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}

	c.token = tr.AccessToken
	exp := tr.ExpiresIn
	if exp > 30 {
		exp -= 30 // refresh a little early
	}
	c.tokenExp = time.Now().Add(time.Duration(exp) * time.Second)
	return c.token, nil
}

// getJSON performs an authenticated admin GET against
// /admin/realms/{realm}/{path} and decodes the JSON body into target.
func (c *keycloakHTTPClient) getJSON(ctx context.Context, realm, path string, query url.Values, target any) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	endpoint := c.adminBase + url.PathEscape(realm) + "/" + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("keycloak GET %s failed: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func reqCtx(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (c *keycloakHTTPClient) ListClients(ctx context.Context, realm, clientID string) ([]KeycloakObject, error) {
	var raw []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	q := url.Values{}
	q.Set("clientId", clientID)
	if err := c.getJSON(reqCtx(ctx), realm, "clients", q, &raw); err != nil {
		return nil, err
	}
	out := make([]KeycloakObject, 0, len(raw))
	for _, r := range raw {
		out = append(out, KeycloakObject{ID: r.ID, Match: r.ClientID})
	}
	return out, nil
}

func (c *keycloakHTTPClient) ListUsers(ctx context.Context, realm, username string) ([]KeycloakObject, error) {
	var raw []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	q := url.Values{}
	q.Set("username", username)
	q.Set("exact", "true")
	if err := c.getJSON(reqCtx(ctx), realm, "users", q, &raw); err != nil {
		return nil, err
	}
	out := make([]KeycloakObject, 0, len(raw))
	for _, r := range raw {
		out = append(out, KeycloakObject{ID: r.ID, Match: r.Username})
	}
	return out, nil
}

func (c *keycloakHTTPClient) listNamed(ctx context.Context, realm, path string, query url.Values) ([]KeycloakObject, error) {
	var raw []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.getJSON(reqCtx(ctx), realm, path, query, &raw); err != nil {
		return nil, err
	}
	out := make([]KeycloakObject, 0, len(raw))
	for _, r := range raw {
		out = append(out, KeycloakObject{ID: r.ID, Match: r.Name})
	}
	return out, nil
}

func (c *keycloakHTTPClient) ListClientScopes(ctx context.Context, realm string) ([]KeycloakObject, error) {
	return c.listNamed(ctx, realm, "client-scopes", nil)
}

func (c *keycloakHTTPClient) ListRealmRoles(ctx context.Context, realm string) ([]KeycloakObject, error) {
	return c.listNamed(ctx, realm, "roles", nil)
}

func (c *keycloakHTTPClient) ListClientRoles(ctx context.Context, realm, clientGUID string) ([]KeycloakObject, error) {
	return c.listNamed(ctx, realm, "clients/"+url.PathEscape(clientGUID)+"/roles", nil)
}

func (c *keycloakHTTPClient) ListTopLevelGroups(ctx context.Context, realm string) ([]KeycloakObject, error) {
	return c.listNamed(ctx, realm, "groups", nil)
}

func (c *keycloakHTTPClient) ListUserFederations(ctx context.Context, realm string) ([]KeycloakObject, error) {
	q := url.Values{}
	q.Set("type", "org.keycloak.storage.UserStorageProvider")
	return c.listNamed(ctx, realm, "components", q)
}

func (c *keycloakHTTPClient) ListAuthenticationFlows(ctx context.Context, realm string) ([]KeycloakObject, error) {
	var raw []struct {
		ID    string `json:"id"`
		Alias string `json:"alias"`
	}
	if err := c.getJSON(reqCtx(ctx), realm, "authentication/flows", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]KeycloakObject, 0, len(raw))
	for _, r := range raw {
		out = append(out, KeycloakObject{ID: r.ID, Match: r.Alias})
	}
	return out, nil
}
