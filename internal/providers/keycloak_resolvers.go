package providers

import (
	"log"
	"regexp"
	"strings"
)

// indexSuffix matches Terraform address indices (e.g. `["bar"]`, `[0]`), which
// appear in plan resource addresses but not in config resource addresses.
var indexSuffix = regexp.MustCompile(`\[[^\]]+\]`)

// KeycloakStatus describes the outcome of attempting to resolve a resource's
// import ID against the Keycloak admin API.
type KeycloakStatus int

const (
	// KeycloakUnsupported means this resource type is not handled by the custom
	// resolver (the generated static mapping applies instead).
	KeycloakUnsupported KeycloakStatus = iota
	// KeycloakSkipped means a prerequisite was missing (no realm, no
	// credentials, an unresolved parent, or the natural key was absent), so no
	// lookup was attempted.
	KeycloakSkipped
	// KeycloakResolved means exactly one object matched and ImportID is set.
	KeycloakResolved
	// KeycloakNotFound means zero objects matched the natural key — typically a
	// genuinely new resource that should be created rather than imported.
	KeycloakNotFound
	// KeycloakAmbiguous means more than one object matched; Candidates lists
	// them so the ambiguity can be surfaced to the user.
	KeycloakAmbiguous
	// KeycloakError means the API lookup failed.
	KeycloakError
)

// KeycloakResolution is the rich result of an import-ID resolution attempt. The
// core tool currently only consumes ImportID (via the string shim below), but
// this type lets a future change surface the NotFound vs Ambiguous distinction
// and the candidate matches to the user without altering this package.
type KeycloakResolution struct {
	Status     KeycloakStatus
	ImportID   string
	Key        string           // the natural key that was searched for
	Candidates []KeycloakObject // populated when Status == KeycloakAmbiguous
}

// resolveCustomextractKeycloakImportID is the hook invoked by the generated
// mapping. It preserves the original string contract: a non-empty ID only when
// exactly one object matched; "" for every other outcome (not found, ambiguous,
// error, unsupported). Richer information is available via ResolveKeycloakImportID.
func resolveCustomextractKeycloakImportID(ctx *ProviderContext, resourceType string, config map[string]any) string {
	return ResolveKeycloakImportID(ctx, resourceType, config).ImportID
}

// ResolveKeycloakImportID resolves the server-generated portion of a Keycloak
// resource's import ID by querying the admin API. To avoid emitting a wrong ID,
// it returns KeycloakResolved only when exactly one object matches the resource's
// natural key; zero or multiple matches are reported distinctly.
//
// Nested resources are keyed by a parent whose GUID is resolved either from
// concrete config (when the parent already exists in state) or by tracing the
// Terraform reference to a parent that is being imported in the same plan (the
// Expression Tracer pattern, via resolveAttribute).
func ResolveKeycloakImportID(ctx *ProviderContext, resourceType string, config map[string]any) KeycloakResolution {
	realm := keycloakRealm(config)
	if realm == "" || ctx == nil {
		return KeycloakResolution{Status: KeycloakSkipped}
	}
	client := ctx.GetKeycloakClient()
	if client == nil {
		return KeycloakResolution{Status: KeycloakSkipped}
	}
	apiCtx := ctx.Context
	realmPrefix := realm + "/"

	switch resourceType {

	// --- Top-level resources keyed by a natural key in config ---------------

	case "keycloak_openid_client", "keycloak_saml_client":
		clientID := configString(config, "client_id")
		if clientID == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListClients(apiCtx, realm, clientID)
		return resolveUnique(realmPrefix, clientID, objs, err)

	case "keycloak_user":
		username := configString(config, "username")
		if username == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListUsers(apiCtx, realm, username)
		return resolveUnique(realmPrefix, username, objs, err)

	case "keycloak_openid_client_scope", "keycloak_saml_client_scope":
		name := configString(config, "name")
		if name == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListClientScopes(apiCtx, realm)
		return resolveUnique(realmPrefix, name, objs, err)

	case "keycloak_role":
		name := configString(config, "name")
		if name == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		// keycloak_role.client_id (when set) is the owning client's GUID.
		if clientGUID := tracedGUID(ctx, config, "client_id"); clientGUID != "" {
			objs, err := client.ListClientRoles(apiCtx, realm, clientGUID)
			return resolveUnique(realmPrefix, name, objs, err)
		}
		objs, err := client.ListRealmRoles(apiCtx, realm)
		return resolveUnique(realmPrefix, name, objs, err)

	case "keycloak_authentication_flow":
		alias := configString(config, "alias")
		if alias == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListAuthenticationFlows(apiCtx, realm)
		return resolveUnique(realmPrefix, alias, objs, err)

	case "keycloak_ldap_user_federation", "keycloak_custom_user_federation":
		name := configString(config, "name")
		if name == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListUserFederations(apiCtx, realm)
		return resolveUnique(realmPrefix, name, objs, err)

	// --- Groups (top-level or nested) ---------------------------------------

	case "keycloak_group":
		name := configString(config, "name")
		if name == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		// A group's import ID is always realm/groupGUID regardless of nesting.
		if parentGUID := tracedGUID(ctx, config, "parent_id"); parentGUID != "" {
			objs, err := client.ListSubGroups(apiCtx, realm, parentGUID)
			return resolveUnique(realmPrefix, name, objs, err)
		}
		if configReferences(ctx, "parent_id") {
			// Nested group whose parent could not be resolved yet.
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListTopLevelGroups(apiCtx, realm)
		return resolveUnique(realmPrefix, name, objs, err)

	// --- LDAP mappers: parent is a user federation --------------------------

	case "keycloak_ldap_user_attribute_mapper",
		"keycloak_ldap_group_mapper",
		"keycloak_ldap_full_name_mapper",
		"keycloak_ldap_role_mapper",
		"keycloak_ldap_hardcoded_attribute_mapper",
		"keycloak_ldap_hardcoded_group_mapper",
		"keycloak_ldap_hardcoded_role_mapper",
		"keycloak_ldap_msad_user_account_control_mapper",
		"keycloak_ldap_msad_lds_user_account_control_mapper",
		"keycloak_ldap_custom_mapper",
		"keycloak_hardcoded_attribute_mapper":
		name := configString(config, "name")
		fedGUID := tracedGUID(ctx, config, "ldap_user_federation_id")
		if name == "" || fedGUID == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListLdapMappers(apiCtx, realm, fedGUID)
		return resolveUnique(realmPrefix+fedGUID+"/", name, objs, err)

	// --- Protocol mappers: parent is a client or a client scope -------------

	case "keycloak_openid_user_attribute_protocol_mapper",
		"keycloak_openid_user_property_protocol_mapper",
		"keycloak_openid_user_client_role_protocol_mapper",
		"keycloak_openid_user_realm_role_protocol_mapper",
		"keycloak_openid_user_session_note_protocol_mapper",
		"keycloak_openid_group_membership_protocol_mapper",
		"keycloak_openid_full_name_protocol_mapper",
		"keycloak_openid_audience_protocol_mapper",
		"keycloak_openid_audience_resolve_protocol_mapper",
		"keycloak_openid_hardcoded_claim_protocol_mapper",
		"keycloak_openid_hardcoded_role_protocol_mapper",
		"keycloak_openid_sub_protocol_mapper",
		"keycloak_saml_user_attribute_protocol_mapper",
		"keycloak_saml_user_property_protocol_mapper",
		"keycloak_generic_protocol_mapper",
		"keycloak_generic_client_protocol_mapper":
		name := configString(config, "name")
		if name == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		if clientGUID := tracedGUID(ctx, config, "client_id"); clientGUID != "" {
			objs, err := client.ListClientProtocolMappers(apiCtx, realm, clientGUID)
			return resolveUnique(realmPrefix+"client/"+clientGUID+"/", name, objs, err)
		}
		if scopeGUID := tracedGUID(ctx, config, "client_scope_id"); scopeGUID != "" {
			objs, err := client.ListClientScopeProtocolMappers(apiCtx, realm, scopeGUID)
			return resolveUnique(realmPrefix+"client-scope/"+scopeGUID+"/", name, objs, err)
		}
		return KeycloakResolution{Status: KeycloakSkipped}

	// --- Identity provider mappers: parent identified by a plain alias ------

	case "keycloak_custom_identity_provider_mapper",
		"keycloak_attribute_importer_identity_provider_mapper",
		"keycloak_attribute_to_role_identity_provider_mapper",
		"keycloak_hardcoded_attribute_identity_provider_mapper",
		"keycloak_hardcoded_group_identity_provider_mapper",
		"keycloak_hardcoded_role_identity_provider_mapper",
		"keycloak_user_template_importer_identity_provider_mapper":
		name := configString(config, "name")
		alias := configString(config, "identity_provider_alias")
		if name == "" || alias == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListIdentityProviderMappers(apiCtx, realm, alias)
		return resolveUnique(realmPrefix+alias+"/", name, objs, err)

	// --- Authorization objects: parent is a resource-server client ----------

	case "keycloak_openid_client_authorization_resource":
		return resolveAuthz(ctx, client, realm, config, "resource")
	case "keycloak_openid_client_authorization_scope":
		return resolveAuthz(ctx, client, realm, config, "scope")
	case "keycloak_openid_client_authorization_permission":
		return resolveAuthz(ctx, client, realm, config, "permission")
	case "keycloak_openid_client_aggregate_policy",
		"keycloak_openid_client_client_policy",
		"keycloak_openid_client_group_policy",
		"keycloak_openid_client_role_policy",
		"keycloak_openid_client_user_policy",
		"keycloak_openid_client_client_scope_policy",
		"keycloak_openid_client_regex_policy",
		"keycloak_openid_client_time_policy":
		return resolveAuthz(ctx, client, realm, config, "policy")
	}

	return KeycloakResolution{Status: KeycloakUnsupported}
}

func resolveAuthz(ctx *ProviderContext, client KeycloakClient, realm string, config map[string]any, kind string) KeycloakResolution {
	name := configString(config, "name")
	rsGUID := tracedGUID(ctx, config, "resource_server_id")
	if name == "" || rsGUID == "" {
		return KeycloakResolution{Status: KeycloakSkipped}
	}
	objs, err := client.ListAuthorizationObjects(ctx.Context, realm, rsGUID, kind)
	return resolveUnique(realm+"/"+rsGUID+"/", name, objs, err)
}

// resolveUnique returns Resolved with prefix+GUID only when exactly one object
// matches key, reporting NotFound, Ambiguous, or Error otherwise.
func resolveUnique(prefix, key string, objs []KeycloakObject, err error) KeycloakResolution {
	if err != nil {
		log.Printf("Keycloak: lookup for %q failed: %v", key, err)
		return KeycloakResolution{Status: KeycloakError, Key: key}
	}
	var matches []KeycloakObject
	for _, o := range objs {
		if o.Match == key {
			matches = append(matches, o)
		}
	}
	switch len(matches) {
	case 1:
		return KeycloakResolution{Status: KeycloakResolved, ImportID: prefix + matches[0].ID, Key: key}
	case 0:
		return KeycloakResolution{Status: KeycloakNotFound, Key: key}
	default:
		log.Printf("Keycloak: found %d objects matching %q; cannot resolve ID unambiguously", len(matches), key)
		return KeycloakResolution{Status: KeycloakAmbiguous, Key: key, Candidates: matches}
	}
}

// keycloakRealm extracts the realm name from config, mirroring the
// realm_id/realm fallback used by the generated mappings.
func keycloakRealm(config map[string]any) string {
	if v := configString(config, "realm_id"); v != "" {
		return v
	}
	return configString(config, "realm")
}

func configString(config map[string]any, key string) string {
	if v, ok := config[key].(string); ok {
		return v
	}
	return ""
}

// tracedGUID resolves a parent reference attribute to the parent's
// server-generated GUID. It returns the concrete value when the parent already
// exists in state, otherwise it traces the Terraform reference to a parent being
// imported in the same plan and extracts the GUID from that parent's import ID.
func tracedGUID(ctx *ProviderContext, config map[string]any, attr string) string {
	v := resolveAttribute(ctx, config, attr)
	if v == "" {
		return ""
	}
	if i := strings.LastIndex(v, "/"); i >= 0 {
		return v[i+1:]
	}
	return v
}

// configReferences reports whether the given attribute is set in the resource's
// configuration via a reference expression (even though its value is computed
// and therefore absent from the plan's after-state).
func configReferences(ctx *ProviderContext, attr string) bool {
	if ctx == nil || ctx.Plan == nil || ctx.Plan.Config == nil || ctx.CurrentResource == nil {
		return false
	}
	address := indexSuffix.ReplaceAllString(ctx.CurrentResource.Address, "")
	cfgRes := findConfigResource(ctx.Plan.Config.RootModule, address)
	if cfgRes == nil {
		return false
	}
	expr, ok := cfgRes.Expressions[attr]
	if !ok || expr == nil || expr.ExpressionData == nil {
		return false
	}
	return len(expr.References) > 0
}
