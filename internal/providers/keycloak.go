package providers

import (
	"fmt"
)

// extractKeycloakImportID returns the necessary import ID for a keycloak resource
// based on its configuration extracted from the terraform plan.
func extractKeycloakImportID(ctx *ProviderContext, resourceType string, config map[string]any) string {
	// First, check if there's a custom resolver for this resource
	if id := resolveCustomextractKeycloakImportID(ctx, resourceType, config); id != "" {
		return id
	}

	switch resourceType {
	case "keycloak_attribute_importer_identity_provider_mapper":
		// Contains server-generated ID: {{realm_id}}/{{idp_alias}}/{{idp_mapper_id}}
		return ""
	case "keycloak_attribute_to_role_identity_provider_mapper":
		// Contains server-generated ID: {{realm_id}}/{{idp_alias}}/{{idp_mapper_id}}
		return ""
	case "keycloak_authentication_bindings":
		// No standard import format found in documentation
		return ""
	case "keycloak_authentication_execution":
		// Contains server-generated ID: {{realmId}}/{{parentFlowAlias}}/{{authenticationExecutionId}}
		return ""
	case "keycloak_authentication_execution_config":
		// Contains server-generated ID: {{realm}}/{{authenticationExecutionId}}/{{authenticationExecutionConfigId}}
		return ""
	case "keycloak_authentication_flow":
		// Contains server-generated ID: {{realmId}}/{{authenticationFlowId}}
		return ""
	case "keycloak_authentication_subflow":
		// Contains server-generated ID: {{realmId}}/{{parentFlowAlias}}/{{authenticationSubflowId}}
		return ""
	case "keycloak_custom_identity_provider_mapper":
		// Contains server-generated ID: {{realm_id}}/{{idp_alias}}/{{idp_mapper_id}}
		return ""
	case "keycloak_custom_user_federation":
		// Contains server-generated ID: {{realm_id}}/{{custom_user_federation_id}}
		return ""
	case "keycloak_default_groups":
		// Format: {{realm}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			if p0 != "" {
				return p0
			}
		}
		return ""
	case "keycloak_default_roles":
		// Contains server-generated ID: {{realm_id}}/{{default_role_id}}
		return ""
	case "keycloak_generic_client_protocol_mapper":
		// Contains server-generated ID: {{realm_id}}/client/{{client_keycloak_id}}/{{protocol_mapper_id}}
		return ""
	case "keycloak_generic_client_role_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_generic_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_generic_role_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_group":
		// Contains server-generated ID: {{realm_id}}/{{group_id}}
		return ""
	case "keycloak_group_memberships":
		// Resource does not support import
		return ""
	case "keycloak_group_permissions":
		// No standard import format found in documentation
		return ""
	case "keycloak_group_roles":
		// Contains server-generated ID: {{realm_id}}/{{group_id}}
		return ""
	case "keycloak_hardcoded_attribute_identity_provider_mapper":
		// No standard import format found in documentation
		return ""
	case "keycloak_hardcoded_attribute_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{attribute__mapper_id}}
		return ""
	case "keycloak_hardcoded_group_identity_provider_mapper":
		// No standard import format found in documentation
		return ""
	case "keycloak_hardcoded_role_identity_provider_mapper":
		// No standard import format found in documentation
		return ""
	case "keycloak_identity_provider_token_exchange_scope_permission":
		// Contains server-generated ID: {{realm_id}}/{{provider_alias}}
		return ""
	case "keycloak_kubernetes_identity_provider":
		// Format: {{realm}}/{{alias}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			var p1 string
			if p1 == "" {
				if v, ok := config["alias"].(string); ok {
					p1 = v
				}
			}
			if p0 != "" && p1 != "" {
				return fmt.Sprintf("%s/%s", p0, p1)
			}
		}
		return ""
	case "keycloak_ldap_custom_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_full_name_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_group_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_hardcoded_attribute_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_hardcoded_group_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_hardcoded_role_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_msad_lds_user_account_control_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_msad_user_account_control_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_role_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_user_attribute_mapper":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}/{{ldap_mapper_id}}
		return ""
	case "keycloak_ldap_user_federation":
		// Contains server-generated ID: {{realm_id}}/{{ldap_user_federation_id}}
		return ""
	case "keycloak_oidc_facebook_identity_provider":
		// No standard import format found in documentation
		return ""
	case "keycloak_oidc_github_identity_provider":
		// No standard import format found in documentation
		return ""
	case "keycloak_oidc_google_identity_provider":
		// No standard import format found in documentation
		return ""
	case "keycloak_oidc_identity_provider":
		// Format: {{realm}}/{{alias}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			var p1 string
			if p1 == "" {
				if v, ok := config["alias"].(string); ok {
					p1 = v
				}
			}
			if p0 != "" && p1 != "" {
				return fmt.Sprintf("%s/%s", p0, p1)
			}
		}
		return ""
	case "keycloak_openid_audience_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_audience_resolve_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_client":
		// Contains server-generated ID: {{realm_id}}/{{client_keycloak_id}}
		return ""
	case "keycloak_openid_client_aggregate_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_authorization_client_scope_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_authorization_permission":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{permissionId}}
		return ""
	case "keycloak_openid_client_authorization_resource":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{authorizationResourceId}}
		return ""
	case "keycloak_openid_client_authorization_scope":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{authorizationScopeId}}
		return ""
	case "keycloak_openid_client_client_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_default_scopes":
		// Resource does not support import
		return ""
	case "keycloak_openid_client_group_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_optional_scopes":
		// Resource does not support import
		return ""
	case "keycloak_openid_client_permissions":
		// No standard import format found in documentation
		return ""
	case "keycloak_openid_client_regex_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_role_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_scope":
		// Contains server-generated ID: {{realm_id}}/{{client_scope_id}}
		return ""
	case "keycloak_openid_client_service_account_realm_role":
		// Contains server-generated ID: {{realmId}}/{{serviceAccountUserId}}/{{roleId}}
		return ""
	case "keycloak_openid_client_service_account_role":
		// Contains server-generated ID: {{realmId}}/{{serviceAccountUserId}}/{{clientId}}/{{roleId}}
		return ""
	case "keycloak_openid_client_time_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_client_user_policy":
		// Contains server-generated ID: {{realmId}}/{{resourceServerId}}/{{policyId}}
		return ""
	case "keycloak_openid_full_name_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_group_membership_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_hardcoded_claim_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_hardcoded_role_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_sub_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_user_attribute_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_user_client_role_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_user_property_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_user_realm_role_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_openid_user_session_note_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_organization":
		// Contains server-generated ID: {{realm_id}}/{{organization_id}}
		return ""
	case "keycloak_realm":
		// Format: {{realm}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			if p0 != "" {
				return p0
			}
		}
		return ""
	case "keycloak_realm_client_policy_profile":
		// Resource does not support import
		return ""
	case "keycloak_realm_client_policy_profile_policy":
		// Resource does not support import
		return ""
	case "keycloak_realm_default_client_scopes":
		// Resource does not support import
		return ""
	case "keycloak_realm_events":
		// Resource does not support import
		return ""
	case "keycloak_realm_keystore_aes_generated":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_keystore_ecdsa_generated":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_keystore_hmac_generated":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_keystore_java_keystore":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_keystore_rsa":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_keystore_rsa_generated":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_localization":
		// No standard import format found in documentation
		return ""
	case "keycloak_realm_optional_client_scopes":
		// Resource does not support import
		return ""
	case "keycloak_realm_user_profile":
		// Resource does not support import
		return ""
	case "keycloak_required_action":
		// Format: {{realm}}/{{alias}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			var p1 string
			if p1 == "" {
				if v, ok := config["alias"].(string); ok {
					p1 = v
				}
			}
			if p0 != "" && p1 != "" {
				return fmt.Sprintf("%s/%s", p0, p1)
			}
		}
		return ""
	case "keycloak_role":
		// Contains server-generated ID: {{realm_id}}/{{role_id}}
		return ""
	case "keycloak_saml_client":
		// Contains server-generated ID: {{realm_id}}/{{client_keycloak_id}}
		return ""
	case "keycloak_saml_client_default_scopes":
		// Resource does not support import
		return ""
	case "keycloak_saml_client_scope":
		// Contains server-generated ID: {{realm_id}}/{{client_scope_id}}
		return ""
	case "keycloak_saml_identity_provider":
		// Format: {{realm}}/{{alias}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			var p1 string
			if p1 == "" {
				if v, ok := config["alias"].(string); ok {
					p1 = v
				}
			}
			if p0 != "" && p1 != "" {
				return fmt.Sprintf("%s/%s", p0, p1)
			}
		}
		return ""
	case "keycloak_saml_user_attribute_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_saml_user_property_protocol_mapper":
		// Multiple/computed import formats in documentation
		return ""
	case "keycloak_spiffe_identity_provider":
		// Format: {{realm}}/{{alias}}
		{
			var p0 string
			if p0 == "" {
				if v, ok := config["realm_id"].(string); ok {
					p0 = v
				}
			}
			if p0 == "" {
				if v, ok := config["realm"].(string); ok {
					p0 = v
				}
			}
			var p1 string
			if p1 == "" {
				if v, ok := config["alias"].(string); ok {
					p1 = v
				}
			}
			if p0 != "" && p1 != "" {
				return fmt.Sprintf("%s/%s", p0, p1)
			}
		}
		return ""
	case "keycloak_user":
		// Contains server-generated ID: {{realm_id}}/{{user_id}}
		return ""
	case "keycloak_user_groups":
		// Resource does not support import
		return ""
	case "keycloak_user_roles":
		// Contains server-generated ID: {{realm_id}}/{{user_id}}
		return ""
	case "keycloak_user_template_importer_identity_provider_mapper":
		// Contains server-generated ID: {{realm_id}}/{{idp_alias}}/{{idp_mapper_id}}
		return ""
	case "keycloak_users_permissions":
		// No standard import format found in documentation
		return ""
	case "keycloak_workflow":
		// Contains server-generated ID: {{realm}}/{{workflow_id}}
		return ""
	}
	return ""
}
