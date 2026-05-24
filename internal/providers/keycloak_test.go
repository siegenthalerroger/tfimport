package providers

import "testing"

func TestExtractKeycloakImportID(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		config       map[string]any
		want         string
	}{
		{
			name:         "realm imports by name (realm attribute)",
			resourceType: "keycloak_realm",
			config:       map[string]any{"realm": "my-realm"},
			want:         "my-realm",
		},
		{
			name:         "realm_id takes precedence over realm",
			resourceType: "keycloak_realm",
			config:       map[string]any{"realm_id": "from-id", "realm": "from-realm"},
			want:         "from-id",
		},
		{
			name:         "oidc identity provider composes realm/alias",
			resourceType: "keycloak_oidc_identity_provider",
			config:       map[string]any{"realm": "my-realm", "alias": "my-idp"},
			want:         "my-realm/my-idp",
		},
		{
			name:         "saml identity provider composes realm/alias",
			resourceType: "keycloak_saml_identity_provider",
			config:       map[string]any{"realm": "my-realm", "alias": "my-saml-idp"},
			want:         "my-realm/my-saml-idp",
		},
		{
			name:         "default_groups imports by realm_id",
			resourceType: "keycloak_default_groups",
			config:       map[string]any{"realm_id": "my-realm"},
			want:         "my-realm",
		},
		{
			name:         "required_action composes realm_id/alias",
			resourceType: "keycloak_required_action",
			config:       map[string]any{"realm_id": "my-realm", "alias": "my-action"},
			want:         "my-realm/my-action",
		},
		{
			name:         "identity provider missing alias is not importable",
			resourceType: "keycloak_oidc_identity_provider",
			config:       map[string]any{"realm": "my-realm"},
			want:         "",
		},
		{
			name:         "group ID is server-generated and not derivable",
			resourceType: "keycloak_group",
			config:       map[string]any{"realm_id": "my-realm", "name": "my-group"},
			want:         "",
		},
		{
			name:         "user ID is server-generated and not derivable",
			resourceType: "keycloak_user",
			config:       map[string]any{"realm_id": "my-realm", "username": "alice"},
			want:         "",
		},
		{
			name:         "resource that does not support import returns empty",
			resourceType: "keycloak_group_memberships",
			config:       map[string]any{"realm_id": "my-realm"},
			want:         "",
		},
		{
			name:         "unknown keycloak resource returns empty",
			resourceType: "keycloak_does_not_exist",
			config:       map[string]any{"realm_id": "my-realm"},
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKeycloakImportID(nil, tt.resourceType, tt.config)
			if got != tt.want {
				t.Errorf("extractKeycloakImportID(%q, %v) = %q, want %q", tt.resourceType, tt.config, got, tt.want)
			}
		})
	}
}
