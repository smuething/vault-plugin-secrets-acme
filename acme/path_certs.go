package acme

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	POLICY_REUSE           = "reuse"
	POLICY_REVOKE          = "revoke"
	POLICY_ROLLOVER        = "rollover"
	POLICY_ROLLOVER_REVOKE = "rollover_revoke"
)

func pathCerts(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "certs/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.cacheList,
				},
			},
		},
		{
			Pattern: "certs/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "The role to be used for issuing the certificate",
				},
				"common_name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "The common name of the certificate. Use this for the primary domain name",
				},
				"alternative_names": {
					Type:        framework.TypeCommaStringSlice,
					Description: "A list of additional DNS names that will be put into the SAN field of the certificate",
				},
				"policy": {
					Type: framework.TypeString,
					AllowedValues: []interface{}{
						POLICY_REUSE,
						POLICY_REVOKE,
						POLICY_ROLLOVER,
						POLICY_ROLLOVER_REVOKE,
					},
					Default:     POLICY_REUSE,
					Description: "The policy for handling certificates that are already cached by Vault.",
				},
				"certificate_grip": {
					Type:        framework.TypeString,
					Description: "The internal grip used to identify the certificate that must be revoked / rolled over when the policy is not 'reuse'",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.certCreate,
				},
			},
		},
	}
}

func (b *backend) certCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}

	names, err := getNames(data)
	if err != nil {
		return nil, err
	}

	roleName := data.Get("role").(string)
	path := rolePrefix + roleName
	r, err := getRole(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if err = validateNames(b, r, names); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if r.Managed {
		return b.getManagedCertSecret(ctx, req, data, roleName, r, names)
	} else {
		return b.getUnmanagedCertSecret(ctx, req, roleName, r, names)
	}
}

func getCacheKey(r *role, data *framework.FieldData) (string, error) {
	rolePath, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshall role: %v", err)
	}

	d := make(map[string]interface{})
	for key := range data.Schema {
		d[key] = data.Get(key)
	}
	dataPath, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("failed to marshall data: %v", err)
	}

	key := string(rolePath) + string(dataPath)
	hashedKey := sha256.Sum256([]byte(key))

	return fmt.Sprintf("%s%x", cachePrefix, hashedKey), nil
}

func getNames(data *framework.FieldData) ([]string, error) {
	commonName := data.Get("common_name").(string)
	altNames := data.Get("alternative_names").([]string)
	slices.Sort(altNames)
	if slices.Contains(altNames, commonName) {
		return nil, fmt.Errorf("main domain cannot be specified again in alternative_names")
	}
	names := make([]string, len(altNames)+1)
	names[0] = commonName
	copy(names[1:], altNames)

	return names, nil
}

func validateNames(b logical.Backend, r *role, names []string) error {
	b.Logger().Debug("Validate names", "role", r, "names", names)

	isSubdomain := func(domain, root string) bool {
		return strings.HasSuffix(domain, "."+root)
	}

	for _, name := range names {
		var valid bool
		for _, domain := range r.AllowedDomains {
			if (domain == name && r.AllowBareDomains) ||
				(isSubdomain(name, domain) && r.AllowSubdomains) {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("'%s' is not an allowed domain", name)
		}
	}

	return nil
}
