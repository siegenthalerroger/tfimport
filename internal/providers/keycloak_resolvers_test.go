package providers

import (
	"context"
	"errors"
	"testing"
)

type fakeKeycloakClient struct {
	clients      []KeycloakObject
	users        []KeycloakObject
	clientScopes []KeycloakObject
	realmRoles   []KeycloakObject
	clientRoles  map[string][]KeycloakObject
	groups       []KeycloakObject
	flows        []KeycloakObject
	federations  []KeycloakObject
	err          error
}

func (f *fakeKeycloakClient) ListClients(_ context.Context, _, _ string) ([]KeycloakObject, error) {
	return f.clients, f.err
}
func (f *fakeKeycloakClient) ListUsers(_ context.Context, _, _ string) ([]KeycloakObject, error) {
	return f.users, f.err
}
func (f *fakeKeycloakClient) ListClientScopes(_ context.Context, _ string) ([]KeycloakObject, error) {
	return f.clientScopes, f.err
}
func (f *fakeKeycloakClient) ListRealmRoles(_ context.Context, _ string) ([]KeycloakObject, error) {
	return f.realmRoles, f.err
}
func (f *fakeKeycloakClient) ListClientRoles(_ context.Context, _, clientGUID string) ([]KeycloakObject, error) {
	return f.clientRoles[clientGUID], f.err
}
func (f *fakeKeycloakClient) ListTopLevelGroups(_ context.Context, _ string) ([]KeycloakObject, error) {
	return f.groups, f.err
}
func (f *fakeKeycloakClient) ListAuthenticationFlows(_ context.Context, _ string) ([]KeycloakObject, error) {
	return f.flows, f.err
}
func (f *fakeKeycloakClient) ListUserFederations(_ context.Context, _ string) ([]KeycloakObject, error) {
	return f.federations, f.err
}

func ctxWithClient(c KeycloakClient) *ProviderContext {
	p := &ProviderContext{Context: context.Background()}
	p.keycloakOnce.Do(func() {}) // prevent env-based construction from overriding the fake
	p.keycloakClient = c
	return p
}

func TestResolveKeycloakImportID(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		config       map[string]any
		client       *fakeKeycloakClient
		want         string
	}{
		{
			name:         "openid client unique match",
			resourceType: "keycloak_openid_client",
			config:       map[string]any{"realm_id": "my-realm", "client_id": "my-app"},
			client:       &fakeKeycloakClient{clients: []KeycloakObject{{ID: "guid-1", Match: "my-app"}, {ID: "guid-2", Match: "other"}}},
			want:         "my-realm/guid-1",
		},
		{
			name:         "openid client no match returns empty",
			resourceType: "keycloak_openid_client",
			config:       map[string]any{"realm_id": "my-realm", "client_id": "missing"},
			client:       &fakeKeycloakClient{clients: []KeycloakObject{{ID: "guid-1", Match: "my-app"}}},
			want:         "",
		},
		{
			name:         "openid client ambiguous match returns empty",
			resourceType: "keycloak_openid_client",
			config:       map[string]any{"realm_id": "my-realm", "client_id": "dup"},
			client:       &fakeKeycloakClient{clients: []KeycloakObject{{ID: "guid-1", Match: "dup"}, {ID: "guid-2", Match: "dup"}}},
			want:         "",
		},
		{
			name:         "saml client uses realm fallback attribute",
			resourceType: "keycloak_saml_client",
			config:       map[string]any{"realm": "my-realm", "client_id": "saml-app"},
			client:       &fakeKeycloakClient{clients: []KeycloakObject{{ID: "guid-s", Match: "saml-app"}}},
			want:         "my-realm/guid-s",
		},
		{
			name:         "user unique match",
			resourceType: "keycloak_user",
			config:       map[string]any{"realm_id": "my-realm", "username": "alice"},
			client:       &fakeKeycloakClient{users: []KeycloakObject{{ID: "u-1", Match: "alice"}}},
			want:         "my-realm/u-1",
		},
		{
			name:         "client scope unique match",
			resourceType: "keycloak_openid_client_scope",
			config:       map[string]any{"realm_id": "my-realm", "name": "my-scope"},
			client:       &fakeKeycloakClient{clientScopes: []KeycloakObject{{ID: "cs-1", Match: "my-scope"}}},
			want:         "my-realm/cs-1",
		},
		{
			name:         "realm role unique match",
			resourceType: "keycloak_role",
			config:       map[string]any{"realm_id": "my-realm", "name": "admin"},
			client:       &fakeKeycloakClient{realmRoles: []KeycloakObject{{ID: "r-1", Match: "admin"}}},
			want:         "my-realm/r-1",
		},
		{
			name:         "client role resolved via client GUID in config",
			resourceType: "keycloak_role",
			config:       map[string]any{"realm_id": "my-realm", "name": "viewer", "client_id": "client-guid"},
			client: &fakeKeycloakClient{
				clientRoles: map[string][]KeycloakObject{"client-guid": {{ID: "cr-1", Match: "viewer"}}},
			},
			want: "my-realm/cr-1",
		},
		{
			name:         "client role with computed (absent) client_id returns empty",
			resourceType: "keycloak_role",
			config:       map[string]any{"realm_id": "my-realm", "name": "viewer"},
			client: &fakeKeycloakClient{
				clientRoles: map[string][]KeycloakObject{"client-guid": {{ID: "cr-1", Match: "viewer"}}},
				realmRoles:  []KeycloakObject{},
			},
			want: "",
		},
		{
			name:         "top-level group unique match",
			resourceType: "keycloak_group",
			config:       map[string]any{"realm_id": "my-realm", "name": "engineers"},
			client:       &fakeKeycloakClient{groups: []KeycloakObject{{ID: "g-1", Match: "engineers"}}},
			want:         "my-realm/g-1",
		},
		{
			name:         "nested group is not resolved",
			resourceType: "keycloak_group",
			config:       map[string]any{"realm_id": "my-realm", "name": "engineers", "parent_id": "some-parent"},
			client:       &fakeKeycloakClient{groups: []KeycloakObject{{ID: "g-1", Match: "engineers"}}},
			want:         "",
		},
		{
			name:         "authentication flow unique match",
			resourceType: "keycloak_authentication_flow",
			config:       map[string]any{"realm_id": "my-realm", "alias": "my-flow"},
			client:       &fakeKeycloakClient{flows: []KeycloakObject{{ID: "f-1", Match: "my-flow"}}},
			want:         "my-realm/f-1",
		},
		{
			name:         "ldap user federation unique match",
			resourceType: "keycloak_ldap_user_federation",
			config:       map[string]any{"realm_id": "my-realm", "name": "corp-ldap"},
			client:       &fakeKeycloakClient{federations: []KeycloakObject{{ID: "fed-1", Match: "corp-ldap"}}},
			want:         "my-realm/fed-1",
		},
		{
			name:         "api error falls back to empty",
			resourceType: "keycloak_user",
			config:       map[string]any{"realm_id": "my-realm", "username": "alice"},
			client:       &fakeKeycloakClient{err: errors.New("boom")},
			want:         "",
		},
		{
			name:         "missing realm returns empty",
			resourceType: "keycloak_openid_client",
			config:       map[string]any{"client_id": "my-app"},
			client:       &fakeKeycloakClient{clients: []KeycloakObject{{ID: "guid-1", Match: "my-app"}}},
			want:         "",
		},
		{
			name:         "unhandled resource returns empty",
			resourceType: "keycloak_group_memberships",
			config:       map[string]any{"realm_id": "my-realm"},
			client:       &fakeKeycloakClient{},
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ctxWithClient(tt.client)
			got := resolveCustomextractKeycloakImportID(ctx, tt.resourceType, tt.config)
			if got != tt.want {
				t.Errorf("resolveCustomextractKeycloakImportID(%q, %v) = %q, want %q", tt.resourceType, tt.config, got, tt.want)
			}
		})
	}
}

func TestResolveKeycloakImportIDNoClient(t *testing.T) {
	// With no client available (no credentials), resolution must fall back to "".
	ctx := ctxWithClient(nil)
	got := resolveCustomextractKeycloakImportID(ctx, "keycloak_openid_client", map[string]any{
		"realm_id":  "my-realm",
		"client_id": "my-app",
	})
	if got != "" {
		t.Errorf("expected empty fallback with no client, got %q", got)
	}
}
