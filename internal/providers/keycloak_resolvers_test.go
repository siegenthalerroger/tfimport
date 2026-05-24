package providers

import (
	"context"
	"errors"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"
)

type fakeKeycloakClient struct {
	clients      []KeycloakObject
	users        []KeycloakObject
	clientScopes []KeycloakObject
	realmRoles   []KeycloakObject
	clientRoles  map[string][]KeycloakObject
	groups       []KeycloakObject
	subGroups    map[string][]KeycloakObject
	flows        []KeycloakObject
	federations  []KeycloakObject
	ldapMappers  map[string][]KeycloakObject
	clientPM     map[string][]KeycloakObject
	scopePM      map[string][]KeycloakObject
	idpMappers   map[string][]KeycloakObject
	authz        map[string][]KeycloakObject // key: resourceServerGUID + "/" + kind
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
func (f *fakeKeycloakClient) ListSubGroups(_ context.Context, _, parentGUID string) ([]KeycloakObject, error) {
	return f.subGroups[parentGUID], f.err
}
func (f *fakeKeycloakClient) ListLdapMappers(_ context.Context, _, federationGUID string) ([]KeycloakObject, error) {
	return f.ldapMappers[federationGUID], f.err
}
func (f *fakeKeycloakClient) ListClientProtocolMappers(_ context.Context, _, clientGUID string) ([]KeycloakObject, error) {
	return f.clientPM[clientGUID], f.err
}
func (f *fakeKeycloakClient) ListClientScopeProtocolMappers(_ context.Context, _, scopeGUID string) ([]KeycloakObject, error) {
	return f.scopePM[scopeGUID], f.err
}
func (f *fakeKeycloakClient) ListIdentityProviderMappers(_ context.Context, _, alias string) ([]KeycloakObject, error) {
	return f.idpMappers[alias], f.err
}
func (f *fakeKeycloakClient) ListAuthorizationObjects(_ context.Context, _, rsGUID, kind string) ([]KeycloakObject, error) {
	return f.authz[rsGUID+"/"+kind], f.err
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
			name:         "client role with computed (absent) client_id falls back to realm role lookup",
			resourceType: "keycloak_role",
			config:       map[string]any{"realm_id": "my-realm", "name": "viewer"},
			client:       &fakeKeycloakClient{realmRoles: []KeycloakObject{}},
			want:         "",
		},
		{
			name:         "top-level group unique match",
			resourceType: "keycloak_group",
			config:       map[string]any{"realm_id": "my-realm", "name": "engineers"},
			client:       &fakeKeycloakClient{groups: []KeycloakObject{{ID: "g-1", Match: "engineers"}}},
			want:         "my-realm/g-1",
		},
		{
			name:         "nested group resolved under concrete parent GUID",
			resourceType: "keycloak_group",
			config:       map[string]any{"realm_id": "my-realm", "name": "backend", "parent_id": "parent-guid"},
			client:       &fakeKeycloakClient{subGroups: map[string][]KeycloakObject{"parent-guid": {{ID: "child-guid", Match: "backend"}}}},
			want:         "my-realm/child-guid",
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
			name:         "ldap mapper resolved under concrete federation GUID",
			resourceType: "keycloak_ldap_group_mapper",
			config:       map[string]any{"realm_id": "my-realm", "name": "group-mapper", "ldap_user_federation_id": "fed-1"},
			client:       &fakeKeycloakClient{ldapMappers: map[string][]KeycloakObject{"fed-1": {{ID: "m-1", Match: "group-mapper"}}}},
			want:         "my-realm/fed-1/m-1",
		},
		{
			name:         "protocol mapper on concrete client GUID",
			resourceType: "keycloak_openid_user_attribute_protocol_mapper",
			config:       map[string]any{"realm_id": "my-realm", "name": "email", "client_id": "client-guid"},
			client:       &fakeKeycloakClient{clientPM: map[string][]KeycloakObject{"client-guid": {{ID: "pm-1", Match: "email"}}}},
			want:         "my-realm/client/client-guid/pm-1",
		},
		{
			name:         "protocol mapper on concrete client scope GUID",
			resourceType: "keycloak_openid_group_membership_protocol_mapper",
			config:       map[string]any{"realm_id": "my-realm", "name": "groups", "client_scope_id": "scope-guid"},
			client:       &fakeKeycloakClient{scopePM: map[string][]KeycloakObject{"scope-guid": {{ID: "pm-2", Match: "groups"}}}},
			want:         "my-realm/client-scope/scope-guid/pm-2",
		},
		{
			name:         "identity provider mapper keyed by alias",
			resourceType: "keycloak_hardcoded_role_identity_provider_mapper",
			config:       map[string]any{"realm_id": "my-realm", "name": "role-mapper", "identity_provider_alias": "my-idp"},
			client:       &fakeKeycloakClient{idpMappers: map[string][]KeycloakObject{"my-idp": {{ID: "im-1", Match: "role-mapper"}}}},
			want:         "my-realm/my-idp/im-1",
		},
		{
			name:         "authorization permission on concrete resource server GUID",
			resourceType: "keycloak_openid_client_authorization_permission",
			config:       map[string]any{"realm_id": "my-realm", "name": "my-perm", "resource_server_id": "rs-guid"},
			client:       &fakeKeycloakClient{authz: map[string][]KeycloakObject{"rs-guid/permission": {{ID: "perm-1", Match: "my-perm"}}}},
			want:         "my-realm/rs-guid/perm-1",
		},
		{
			name:         "authorization policy on concrete resource server GUID",
			resourceType: "keycloak_openid_client_role_policy",
			config:       map[string]any{"realm_id": "my-realm", "name": "my-policy", "resource_server_id": "rs-guid"},
			client:       &fakeKeycloakClient{authz: map[string][]KeycloakObject{"rs-guid/policy": {{ID: "pol-1", Match: "my-policy"}}}},
			want:         "my-realm/rs-guid/pol-1",
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

// TestResolveKeycloakStatus verifies the richer resolution that distinguishes
// not-found from ambiguous (and surfaces the candidate matches).
func TestResolveKeycloakStatus(t *testing.T) {
	t.Run("resolved", func(t *testing.T) {
		ctx := ctxWithClient(&fakeKeycloakClient{clients: []KeycloakObject{{ID: "g1", Match: "app"}}})
		res := ResolveKeycloakImportID(ctx, "keycloak_openid_client", map[string]any{"realm_id": "r", "client_id": "app"})
		if res.Status != KeycloakResolved || res.ImportID != "r/g1" {
			t.Fatalf("got status=%v id=%q", res.Status, res.ImportID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctx := ctxWithClient(&fakeKeycloakClient{clients: []KeycloakObject{{ID: "g1", Match: "other"}}})
		res := ResolveKeycloakImportID(ctx, "keycloak_openid_client", map[string]any{"realm_id": "r", "client_id": "app"})
		if res.Status != KeycloakNotFound {
			t.Fatalf("expected KeycloakNotFound, got %v", res.Status)
		}
		if len(res.Candidates) != 0 {
			t.Fatalf("expected no candidates, got %v", res.Candidates)
		}
	})

	t.Run("ambiguous surfaces candidates", func(t *testing.T) {
		ctx := ctxWithClient(&fakeKeycloakClient{groups: []KeycloakObject{
			{ID: "g1", Match: "dup"}, {ID: "g2", Match: "dup"}, {ID: "g3", Match: "unique"},
		}})
		res := ResolveKeycloakImportID(ctx, "keycloak_group", map[string]any{"realm_id": "r", "name": "dup"})
		if res.Status != KeycloakAmbiguous {
			t.Fatalf("expected KeycloakAmbiguous, got %v", res.Status)
		}
		if len(res.Candidates) != 2 {
			t.Fatalf("expected 2 candidates, got %d: %v", len(res.Candidates), res.Candidates)
		}
		if res.ImportID != "" {
			t.Fatalf("ambiguous result must not produce an ImportID, got %q", res.ImportID)
		}
	})

	t.Run("skipped without credentials", func(t *testing.T) {
		ctx := ctxWithClient(nil)
		res := ResolveKeycloakImportID(ctx, "keycloak_openid_client", map[string]any{"realm_id": "r", "client_id": "app"})
		if res.Status != KeycloakSkipped {
			t.Fatalf("expected KeycloakSkipped, got %v", res.Status)
		}
	})

	t.Run("unsupported resource", func(t *testing.T) {
		ctx := ctxWithClient(&fakeKeycloakClient{})
		res := ResolveKeycloakImportID(ctx, "keycloak_realm", map[string]any{"realm_id": "r"})
		if res.Status != KeycloakUnsupported {
			t.Fatalf("expected KeycloakUnsupported, got %v", res.Status)
		}
	})
}

// TestResolveKeycloakTracedParent verifies that a nested resource whose parent
// GUID is computed (because the parent is being imported in the same plan) is
// resolved by tracing the Terraform reference to that parent and recursively
// resolving the parent's GUID.
func TestResolveKeycloakTracedParent(t *testing.T) {
	const childAddr = "keycloak_openid_user_attribute_protocol_mapper.m"
	const parentAddr = "keycloak_openid_client.app"

	plan := &tfjson.Plan{
		Config: &tfjson.Config{
			RootModule: &tfjson.ConfigModule{
				Resources: []*tfjson.ConfigResource{
					{
						Address: childAddr,
						Expressions: map[string]*tfjson.Expression{
							"client_id": {ExpressionData: &tfjson.ExpressionData{
								References: []string{parentAddr + ".id", parentAddr},
							}},
						},
					},
				},
			},
		},
		ResourceChanges: []*tfjson.ResourceChange{
			{
				Address: parentAddr,
				Type:    "keycloak_openid_client",
				Change:  &tfjson.Change{After: map[string]any{"realm_id": "my-realm", "client_id": "app"}},
			},
		},
	}

	fake := &fakeKeycloakClient{
		clients:  []KeycloakObject{{ID: "client-guid", Match: "app"}},
		clientPM: map[string][]KeycloakObject{"client-guid": {{ID: "pm-guid", Match: "my-mapper"}}},
	}

	ctx := ctxWithClient(fake)
	ctx.Plan = plan
	ctx.CurrentResource = &tfjson.ResourceChange{Address: childAddr, Type: "keycloak_openid_user_attribute_protocol_mapper"}

	// client_id is computed (absent from the child's config), forcing a trace.
	childConfig := map[string]any{"realm_id": "my-realm", "name": "my-mapper"}
	got := resolveCustomextractKeycloakImportID(ctx, "keycloak_openid_user_attribute_protocol_mapper", childConfig)
	want := "my-realm/client/client-guid/pm-guid"
	if got != want {
		t.Fatalf("traced parent resolution = %q, want %q", got, want)
	}
}

func TestResolveKeycloakImportIDNoClient(t *testing.T) {
	ctx := ctxWithClient(nil)
	got := resolveCustomextractKeycloakImportID(ctx, "keycloak_openid_client", map[string]any{
		"realm_id":  "my-realm",
		"client_id": "my-app",
	})
	if got != "" {
		t.Errorf("expected empty fallback with no client, got %q", got)
	}
}
