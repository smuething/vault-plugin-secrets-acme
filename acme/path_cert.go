package acme

import (
	"context"
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

func pathCert(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: certPrefix + framework.GenericNameRegex("role") + "/" + "(?P<domains>((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9],)*(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])",
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "The role to be used for issuing the certificate",
				},
				"domains": {
					Type:        framework.TypeCommaStringSlice,
					Required:    true,
					Description: "The domains for which the certificate will be valid. The first certificate in the list will be set as the common name.",
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
				"cert_id": {
					Type:        framework.TypeString,
					Description: "The ARI certificate ID, or if the ACME CA does not support ARI, the SHA256 thumbprint of the certificate that must be revoked / rolled over when the policy is not 'reuse'",
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
	r, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("Role %s not found", roleName)
	}

	if err = validateNames(b, r, names); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if r.Managed {
		return b.getManagedCertSecret(ctx, req, data, roleName, r, names)
	} else {
		return b.getUnmanagedCert(ctx, req, roleName, r, names)
	}
}

func getNames(data *framework.FieldData) ([]string, error) {
	domains := data.Get("domains").([]string)
	if len(domains) < 1 {
		return nil, fmt.Errorf("No domains specified for the certificate")
	}
	if len(domains) > 1 {
		// canonicalize domains that do not control the CN of the certificate
		slices.Sort(domains[1:])
	}

	return domains, nil
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
