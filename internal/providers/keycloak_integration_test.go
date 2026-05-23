//go:build integration

// Integration tests for the Keycloak resolvers. They run against a real
// Keycloak instance and are excluded from the normal test build.
//
//	Run with a live Keycloak (e.g. `docker run -p 8080:8080 \
//	  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
//	  quay.io/keycloak/keycloak:26.6.1 start-dev`) and then:
//
//		KEYCLOAK_URL=http://localhost:8080 \
//		KEYCLOAK_USER=admin KEYCLOAK_PASSWORD=admin \
//		go test -tags integration ./internal/providers/ -run Integration -v
//
// The test creates a throwaway realm, seeds resources, asserts the resolvers
// return the correct import IDs, and deletes the realm on completion.
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const itRealm = "tfimport-integration"

func TestIntegrationKeycloakResolvers(t *testing.T) {
	client := newKeycloakHTTPClientFromEnv()
	if client == nil {
		t.Skip("set KEYCLOAK_URL and credentials (KEYCLOAK_USER/KEYCLOAK_PASSWORD or KEYCLOAK_CLIENT_SECRET) to run integration tests")
	}

	h := &itHelper{t: t, c: client}
	ctx := context.Background()

	// Fresh realm; delete any leftover from a previous run first.
	h.delete(ctx, "")
	h.createRealm(ctx)
	t.Cleanup(func() { h.delete(context.Background(), "") })

	pctx := ctxWithClient(client)

	// --- Top-level resources ------------------------------------------------

	clientGUID := h.locationID(ctx, "clients", map[string]any{"clientId": "my-app", "enabled": true})
	assertResolve(t, pctx, "keycloak_openid_client",
		map[string]any{"realm_id": itRealm, "client_id": "my-app"},
		itRealm+"/"+clientGUID)

	userGUID := h.locationID(ctx, "users", map[string]any{"username": "alice", "enabled": true})
	assertResolve(t, pctx, "keycloak_user",
		map[string]any{"realm_id": itRealm, "username": "alice"},
		itRealm+"/"+userGUID)

	scopeGUID := h.locationID(ctx, "client-scopes", map[string]any{"name": "my-scope", "protocol": "openid-connect"})
	assertResolve(t, pctx, "keycloak_openid_client_scope",
		map[string]any{"realm_id": itRealm, "name": "my-scope"},
		itRealm+"/"+scopeGUID)

	// Realm role POST Location is the role name, so look the GUID up instead.
	h.post(ctx, "roles", map[string]any{"name": "my-role"})
	roleGUID := h.findID(func() ([]KeycloakObject, error) { return client.ListRealmRoles(ctx, itRealm) }, "my-role")
	assertResolve(t, pctx, "keycloak_role",
		map[string]any{"realm_id": itRealm, "name": "my-role"},
		itRealm+"/"+roleGUID)

	// --- Groups: top-level and nested --------------------------------------

	parentGUID := h.locationID(ctx, "groups", map[string]any{"name": "platform"})
	assertResolve(t, pctx, "keycloak_group",
		map[string]any{"realm_id": itRealm, "name": "platform"},
		itRealm+"/"+parentGUID)

	childGUID := h.locationID(ctx, "groups/"+parentGUID+"/children", map[string]any{"name": "backend"})
	assertResolve(t, pctx, "keycloak_group",
		map[string]any{"realm_id": itRealm, "name": "backend", "parent_id": parentGUID},
		itRealm+"/"+childGUID)

	// --- Nested protocol mapper on the client ------------------------------

	mapperGUID := h.locationID(ctx, "clients/"+clientGUID+"/protocol-mappers/models", map[string]any{
		"name":           "email-mapper",
		"protocol":       "openid-connect",
		"protocolMapper": "oidc-usermodel-attribute-mapper",
		"config": map[string]any{
			"user.attribute":     "email",
			"claim.name":         "email",
			"jsonType.label":     "String",
			"id.token.claim":     "true",
			"access.token.claim": "true",
		},
	})
	assertResolve(t, pctx, "keycloak_openid_user_attribute_protocol_mapper",
		map[string]any{"realm_id": itRealm, "name": "email-mapper", "client_id": clientGUID},
		itRealm+"/client/"+clientGUID+"/"+mapperGUID)

	// --- Not-found vs ambiguous distinction --------------------------------

	if res := ResolveKeycloakImportID(pctx, "keycloak_openid_client",
		map[string]any{"realm_id": itRealm, "client_id": "does-not-exist"}); res.Status != KeycloakNotFound {
		t.Errorf("expected KeycloakNotFound for missing client, got %v", res.Status)
	}
}

func assertResolve(t *testing.T, ctx *ProviderContext, resourceType string, config map[string]any, want string) {
	t.Helper()
	res := ResolveKeycloakImportID(ctx, resourceType, config)
	if res.Status != KeycloakResolved {
		t.Errorf("%s: status = %v, want KeycloakResolved", resourceType, res.Status)
		return
	}
	if res.ImportID != want {
		t.Errorf("%s: ImportID = %q, want %q", resourceType, res.ImportID, want)
	}
}

type itHelper struct {
	t *testing.T
	c *keycloakHTTPClient
}

func (h *itHelper) base() string { return strings.TrimRight(h.c.adminBase, "/") }

func (h *itHelper) do(ctx context.Context, method, fullURL string, body any) *http.Response {
	h.t.Helper()
	token, err := h.c.getToken(ctx)
	if err != nil {
		h.t.Fatalf("token: %v", err)
	}
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		h.t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.c.httpClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, fullURL, err)
	}
	return resp
}

func (h *itHelper) createRealm(ctx context.Context) {
	h.t.Helper()
	resp := h.do(ctx, http.MethodPost, h.base(), map[string]any{"realm": itRealm, "enabled": true})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		h.t.Fatalf("create realm: %s: %s", resp.Status, b)
	}
	// Give Keycloak a moment to fully initialize the realm.
	time.Sleep(500 * time.Millisecond)
}

// post creates an object under the test realm and discards the response.
func (h *itHelper) post(ctx context.Context, path string, body any) {
	h.t.Helper()
	resp := h.do(ctx, http.MethodPost, h.base()+"/"+itRealm+"/"+path, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		h.t.Fatalf("POST %s: %s: %s", path, resp.Status, b)
	}
}

// locationID creates an object and returns its GUID from the Location header.
func (h *itHelper) locationID(ctx context.Context, path string, body any) string {
	h.t.Helper()
	resp := h.do(ctx, http.MethodPost, h.base()+"/"+itRealm+"/"+path, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		h.t.Fatalf("POST %s: %s: %s", path, resp.Status, b)
	}
	loc := resp.Header.Get("Location")
	if i := strings.LastIndex(loc, "/"); i >= 0 {
		return loc[i+1:]
	}
	h.t.Fatalf("POST %s: no Location header", path)
	return ""
}

func (h *itHelper) findID(list func() ([]KeycloakObject, error), key string) string {
	h.t.Helper()
	objs, err := list()
	if err != nil {
		h.t.Fatalf("list: %v", err)
	}
	for _, o := range objs {
		if o.Match == key {
			return o.ID
		}
	}
	h.t.Fatalf("no object matching %q", key)
	return ""
}

// delete removes a path under the test realm; an empty path deletes the realm.
func (h *itHelper) delete(ctx context.Context, path string) {
	url := h.base() + "/" + itRealm
	if path != "" {
		url += "/" + path
	}
	resp := h.do(ctx, http.MethodDelete, url, nil)
	_ = resp.Body.Close() // best-effort cleanup; status ignored
}
