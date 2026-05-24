package providers

import "log"

// KeycloakStatus describes the outcome of attempting to resolve a resource's
// import ID against the Keycloak admin API.
type KeycloakStatus int

const (
	// KeycloakUnsupported means this resource type is not handled by the custom
	// resolver (the generated static mapping applies instead).
	KeycloakUnsupported KeycloakStatus = iota
	// KeycloakSkipped means a prerequisite was missing (no realm, no
	// credentials, or the natural key was absent), so no lookup was attempted.
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
		if clientGUID := configString(config, "client_id"); clientGUID != "" {
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

	case "keycloak_group":
		name := configString(config, "name")
		if name == "" {
			return KeycloakResolution{Status: KeycloakSkipped}
		}
		objs, err := client.ListTopLevelGroups(apiCtx, realm)
		return resolveUnique(realmPrefix, name, objs, err)
	}

	return KeycloakResolution{Status: KeycloakUnsupported}
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
