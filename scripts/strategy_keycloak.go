package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// canonicalToken maps a documentation placeholder (e.g. `realm_id`, `idp_alias`)
// to a canonical token. Keycloak documentation is inconsistent about placeholder
// naming, so only placeholders that are reliably derivable from a resource's
// planned configuration are listed here. Any placeholder not present in this map
// is treated as a server-generated identifier (a GUID assigned by Keycloak on
// creation) and forces the whole resource to be marked computed.
var keycloakCanonicalToken = map[string]string{
	"realm_id":  "realm",
	"realm":     "realm",
	"realmId":   "realm",
	"client_id": "client",
	"clientId":  "client",
	"idp_alias": "alias",
	"alias":     "alias",
	"name":      "name",
}

// keycloakCandidateKeys maps a canonical token to the ordered list of config
// attribute keys to try when building an import ID. The first non-empty value
// wins. The realm fallback exists because most child resources expose `realm_id`
// while identity-provider resources expose `realm`, even though both docs use the
// `{{realm_id}}` placeholder.
var keycloakCandidateKeys = map[string][]string{
	"realm":  {"realm_id", "realm"},
	"client": {"client_id"},
	"alias":  {"alias"},
	"name":   {"name"},
}

func getKeycloakStrategy() ProviderStrategy {
	formatRegex := regexp.MustCompile("`(\\{\\{[^`]+\\}\\})`")
	placeholderRegex := regexp.MustCompile(`\{\{([^}]+)\}\}`)

	return ProviderStrategy{
		// Capture the body of the "## Import" section up to the next "## " heading
		// (or end of file). doc_cruncher treats len(match) > 1 as a successful
		// match; docs without an Import section fall through to its default
		// computed path.
		MatchRegex: regexp.MustCompile(`(?s)## Import\b(.*?)(?:\n##\s|\z)`),
		ExtractFunc: func(match []string) ([]string, bool, string) {
			section := match[1]

			if strings.Contains(strings.ToLower(section), "does not support import") {
				return nil, true, "Resource does not support import"
			}

			formats := formatRegex.FindAllStringSubmatch(section, -1)

			// Realm-style: "imported using their name" with no {{}} format string.
			if len(formats) == 0 {
				lower := strings.ToLower(section)
				if strings.Contains(lower, "their name") || strings.Contains(lower, "using the name") {
					return []string{"{{realm}}"}, false, ""
				}
				return nil, true, "No standard import format found in documentation"
			}

			// Multiple formats (e.g. Client vs Client-Scope protocol mappers) are
			// ambiguous and always contain server-generated IDs.
			if len(formats) > 1 {
				return nil, true, "Multiple/computed import formats in documentation"
			}

			format := formats[0][1]
			placeholders := placeholderRegex.FindAllStringSubmatch(format, -1)

			canonical := format
			for _, p := range placeholders {
				token, ok := keycloakCanonicalToken[strings.TrimSpace(p[1])]
				if !ok {
					return nil, true, fmt.Sprintf("Contains server-generated ID: %s", format)
				}
				canonical = strings.Replace(canonical, "{{"+p[1]+"}}", "{{"+token+"}}", 1)
			}

			return []string{canonical}, false, ""
		},
		GenerateFunc: func(mappings []mapping, funcName, providerName string) string {
			var body bytes.Buffer
			usesFmt := false

			for _, m := range mappings {
				fmt.Fprintf(&body, "\tcase \"%s\":\n", m.Resource)
				if m.IsComputed {
					fmt.Fprintf(&body, "\t\t// %s\n", m.Comment)
					fmt.Fprintf(&body, "\t\treturn \"\"\n")
					continue
				}

				format := m.Keys[0]
				placeholders := placeholderRegex.FindAllStringSubmatch(format, -1)

				fmt.Fprintf(&body, "\t\t// Format: %s\n", format)
				fmt.Fprintf(&body, "\t\t{\n")

				var partVars []string
				for i, p := range placeholders {
					token := p[1]
					candidates := keycloakCandidateKeys[token]
					partVar := fmt.Sprintf("p%d", i)
					partVars = append(partVars, partVar)

					fmt.Fprintf(&body, "\t\t\tvar %s string\n", partVar)
					for _, key := range candidates {
						fmt.Fprintf(&body, "\t\t\tif %s == \"\" {\n", partVar)
						fmt.Fprintf(&body, "\t\t\t\tif v, ok := config[\"%s\"].(string); ok {\n", key)
						fmt.Fprintf(&body, "\t\t\t\t\t%s = v\n", partVar)
						fmt.Fprintf(&body, "\t\t\t\t}\n")
						fmt.Fprintf(&body, "\t\t\t}\n")
					}
				}

				var checks []string
				for _, v := range partVars {
					checks = append(checks, fmt.Sprintf("%s != \"\"", v))
				}
				fmt.Fprintf(&body, "\t\t\tif %s {\n", strings.Join(checks, " && "))

				if len(partVars) == 1 {
					fmt.Fprintf(&body, "\t\t\t\treturn %s\n", partVars[0])
				} else {
					usesFmt = true
					template := placeholderRegex.ReplaceAllString(format, "%s")
					template = strings.ReplaceAll(template, "\"", "\\\"")
					fmt.Fprintf(&body, "\t\t\t\treturn fmt.Sprintf(\"%s\", %s)\n", template, strings.Join(partVars, ", "))
				}

				fmt.Fprintf(&body, "\t\t\t}\n")
				fmt.Fprintf(&body, "\t\t}\n")
				fmt.Fprintf(&body, "\t\treturn \"\"\n")
			}

			var buf bytes.Buffer
			fmt.Fprintf(&buf, "package providers\n\n")
			if usesFmt {
				fmt.Fprintf(&buf, "import (\n\t\"fmt\"\n)\n\n")
			}
			fmt.Fprintf(&buf, `// %s returns the necessary import ID for a %s resource
// based on its configuration extracted from the terraform plan.
func %s(ctx *ProviderContext, resourceType string, config map[string]any) string {
	// First, check if there's a custom resolver for this resource
	if id := resolveCustom%s(ctx, resourceType, config); id != "" {
		return id
	}

	switch resourceType {
`, funcName, providerName, funcName, funcName)
			buf.Write(body.Bytes())
			fmt.Fprintf(&buf, "\t}\n\treturn \"\"\n}\n")
			return buf.String()
		},
	}
}
