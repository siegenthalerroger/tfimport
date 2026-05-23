package providers

import (
	"context"
	"log"
)

// resolveCustomextractKeycloakImportID resolves the server-generated GUID
// portion of a Keycloak resource's import ID by querying the Keycloak admin API.
//
// Most Keycloak import IDs have the form {{realm}}/{{guid}} where the GUID is
// assigned by the server and is therefore absent from the Terraform plan. When
// credentials are available (see GetKeycloakClient) we look the object up by its
// natural key (clientId, username, name, alias, ...). To avoid emitting an
// incorrect import ID, we only return a value when exactly one object matches;
// zero matches (a genuinely new resource) or multiple matches both fall back to
// "" so the resource is reported as not importable.
func resolveCustomextractKeycloakImportID(ctx *ProviderContext, resourceType string, config map[string]any) string {
	realm := keycloakRealm(config)
	if realm == "" || ctx == nil {
		return ""
	}

	client := ctx.GetKeycloakClient()
	if client == nil {
		return ""
	}

	c := ctx.Context

	switch resourceType {
	case "keycloak_openid_client", "keycloak_saml_client":
		clientID := configString(config, "client_id")
		if clientID == "" {
			return ""
		}
		guid := uniqueClientGUID(c, client, realm, clientID)
		return withRealm(realm, guid)

	case "keycloak_user":
		username := configString(config, "username")
		if username == "" {
			return ""
		}
		objs, err := client.ListUsers(c, realm, username)
		return withRealm(realm, uniqueMatch(objs, err, "user", username))

	case "keycloak_openid_client_scope", "keycloak_saml_client_scope":
		name := configString(config, "name")
		if name == "" {
			return ""
		}
		objs, err := client.ListClientScopes(c, realm)
		return withRealm(realm, uniqueMatch(objs, err, "client scope", name))

	case "keycloak_role":
		name := configString(config, "name")
		if name == "" {
			return ""
		}
		// For a client role, keycloak_role.client_id holds the owning client's
		// internal GUID (a reference to keycloak_client.*.id), so it can be used
		// directly. When the client is created in the same plan this value is
		// computed and therefore absent, in which case we fall back to "".
		if clientGUID := configString(config, "client_id"); clientGUID != "" {
			objs, err := client.ListClientRoles(c, realm, clientGUID)
			return withRealm(realm, uniqueMatch(objs, err, "client role", name))
		}
		objs, err := client.ListRealmRoles(c, realm)
		return withRealm(realm, uniqueMatch(objs, err, "realm role", name))

	case "keycloak_group":
		// Only top-level groups are unambiguously resolvable by name; nested
		// groups reference a computed parent_id we cannot resolve here.
		if configString(config, "parent_id") != "" {
			return ""
		}
		name := configString(config, "name")
		if name == "" {
			return ""
		}
		objs, err := client.ListTopLevelGroups(c, realm)
		return withRealm(realm, uniqueMatch(objs, err, "group", name))

	case "keycloak_authentication_flow":
		alias := configString(config, "alias")
		if alias == "" {
			return ""
		}
		objs, err := client.ListAuthenticationFlows(c, realm)
		return withRealm(realm, uniqueMatch(objs, err, "authentication flow", alias))

	case "keycloak_ldap_user_federation", "keycloak_custom_user_federation":
		name := configString(config, "name")
		if name == "" {
			return ""
		}
		objs, err := client.ListUserFederations(c, realm)
		return withRealm(realm, uniqueMatch(objs, err, "user federation", name))
	}

	return ""
}

// keycloakRealm extracts the realm name from a resource's config, mirroring the
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

// uniqueClientGUID returns the GUID of the client whose clientId exactly matches,
// but only when it is unique.
func uniqueClientGUID(ctx context.Context, client KeycloakClient, realm, clientID string) string {
	objs, err := client.ListClients(ctx, realm, clientID)
	return uniqueMatch(objs, err, "client", clientID)
}

// uniqueMatch returns the GUID of the single object whose natural key equals
// key. It returns "" on error, zero matches, or more than one match.
func uniqueMatch(objs []KeycloakObject, err error, kind, key string) string {
	if err != nil {
		log.Printf("Keycloak: failed to look up %s %q: %v", kind, key, err)
		return ""
	}
	var guid string
	count := 0
	for _, o := range objs {
		if o.Match == key {
			guid = o.ID
			count++
		}
	}
	switch {
	case count == 1:
		return guid
	case count > 1:
		log.Printf("Keycloak: found %d %ss matching %q; cannot resolve ID unambiguously", count, kind, key)
	}
	return ""
}

// withRealm prefixes a resolved GUID with the realm to form the import ID,
// returning "" when the GUID could not be resolved.
func withRealm(realm, guid string) string {
	if guid == "" {
		return ""
	}
	return realm + "/" + guid
}
