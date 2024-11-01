package acme

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

type CertificateState int

const (
	ACTIVE CertificateState = iota
	START_ROLL_OVER
	ROLLING_OVER
	EXPIRED
)

func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.roleList,
				},
			},
		},
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:     framework.TypeLowerCaseString,
					Required: true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Name",
						Description: "The name of the role",
						Value:       "role-name",
					},
				},
				"account": {
					Type:     framework.TypeString,
					Required: true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Account",
						Description: "The account ACME account that will be used to request certificates",
						Value:       "<account>",
					},
				},
				"allowed_domains": {
					Type: framework.TypeCommaStringSlice,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Allowed domains",
						Description: "The domains for which this role is allowed to request certificates",
						Value:       "example.com,example.org",
					},
				},
				"allow_bare_domains": {
					Type: framework.TypeBool,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Allow bare domains",
						Description: "Is it allowed to obtain certificates for the domains listed in allowed_domains themselves?",
						Value:       "false",
					},
				},
				"allow_subdomains": {
					Type: framework.TypeBool,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Allow subdomains",
						Description: "Is it alloweed to obtain certificates for subdomains of the domains listed in allowed_domains?",
						Value:       "true",
					},
				},
				"managed": {
					Type:     framework.TypeBool,
					Required: true,
					Default:  true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Create managed certificates",
						Description: "Managed certificates are cached by the plugin and support controlled rollover and revocation. You almost certainly want this!",
						Value:       "true",
					},
				},
				"rollover_time_percentage": {
					Type:    framework.TypeInt,
					Default: 70,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Rollover time percentage",
						Description: "Percentage of certificate validity after which rollover should occur. Only applicable to managed certificats.",
						Value:       "70",
					},
				},
				"rollover_window": {
					Type: framework.TypeDurationSecond,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Rollover window",
						Description: "Length of additional rollover window.",
						Value:       "1d",
					},
				},
				"key_type": {
					Type:          framework.TypeString,
					AllowedValues: keyTypes,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Key Type",
						Description: "Private key type of requested certificates, e.g. EC256",
						Value:       "EC256",
					},
				},
				"revoke_on_expiry": {
					Type: framework.TypeBool,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Revoke on expiry",
						Description: "Whether to revoke managed certificates on cache expiry.",
						Value:       "false",
					},
				},
				"max_ttl": {
					Type: framework.TypeDurationSecond,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Max TTL",
						Description: "The maximum TTL for managed certificates.",
						Value:       "",
					},
				},
				"ttl": {
					Type: framework.TypeDurationSecond,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "TTL",
						Description: "The TTL of managed certificates.",
						Value:       "",
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.roleCreateOrUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.roleRead,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.roleCreateOrUpdate,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.roleDelete,
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
		},
	}
}

func (b *backend) roleCreateOrUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	name := data.Get("name").(string)
	b.Logger().Info("validating input")
	if err := data.Validate(); err != nil {
		return nil, err
	}

	rolloverTimePercentage := data.Get("rollover_time_percentage").(int)
	if rolloverTimePercentage <= 0 || rolloverTimePercentage > 100 {
		return logical.ErrorResponse("rollover_time_percentage should be greater than 0 and less than 100"), nil
	}

	r := role{
		Account:                data.Get("account").(string),
		AllowedDomains:         data.Get("allowed_domains").([]string),
		AllowBareDomains:       data.Get("allow_bare_domains").(bool),
		AllowSubdomains:        data.Get("allow_subdomains").(bool),
		Managed:                data.Get("managed").(bool),
		RolloverTimePercentage: data.Get("rollover_time_percentage").(int),
		RolloverWindow:         time.Duration(data.Get("rollover_window").(int)) * time.Second,
		KeyType:                data.Get("key_type").(string),
		RevokeOnExpiry:         data.Get("revoke_on_expiry").(bool),
		MaxTTL:                 time.Duration(data.Get("max_ttl").(int)) * time.Second,
		TTL:                    time.Duration(data.Get("ttl").(int)) * time.Second,
	}
	b.Logger().Info("saving role")
	if err := r.save(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	b.Logger().Info("reading role")
	return b.roleRead(ctx, req, data)
}

func (b *backend) roleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Retrieving role from storage")
	name := data.Get("name").(string)

	r, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("This role does not exists"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account":                  r.Account,
			"allowed_domains":          r.AllowedDomains,
			"allow_bare_domains":       r.AllowBareDomains,
			"allow_subdomains":         r.AllowSubdomains,
			"managed":                  r.Managed,
			"rollover_time_percentage": r.RolloverTimePercentage,
			"rollover_window":          r.RolloverWindow.Seconds(),
			"key_type":                 r.KeyType,
			"revoke_on_expiry":         r.RevokeOnExpiry,
			"max_ttl":                  r.MaxTTL.Seconds(),
			"ttl":                      r.TTL.Seconds(),
		},
	}, nil
}

func (b *backend) roleDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, req.Path)
}

func (b *backend) roleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, rolePrefix)
	if err != nil {
		return nil, err
	}

	info := make(map[string]any)
	for _, key := range entries {
		role, err := getRole(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		info[key] = &map[string]any{
			"Managed":         role.Managed,
			"Account":         role.Account,
			"Allowed domains": role.AllowedDomains,
			"Key type":        role.KeyType,
			"TTL":             role.TTL.String(),
		}
	}

	return logical.ListResponseWithInfo(entries, info), nil
}

type role struct {
	Account                string        `json:"account"`
	AllowedDomains         []string      `json:"allowed_domains"`
	AllowBareDomains       bool          `json:"allow_bare_domains"`
	AllowSubdomains        bool          `json:"allow_subdomains"`
	Managed                bool          `json:"managed"`
	RolloverTimePercentage int           `json:"rollover_time_percentage"`
	RolloverWindow         time.Duration `json:"rollover_window"`
	KeyType                string        `json:"key_type"`
	RevokeOnExpiry         bool          `json:"revoke_on_expiry"`
	MaxTTL                 time.Duration `json:"max_ttl"`
	TTL                    time.Duration `json:"ttl"`
}

func (r *role) CertificateState(cert *CachedCertificate) (CertificateState, time.Duration) {
	now := time.Now()
	if now.After(cert.NotAfter) {
		return EXPIRED, 0
	}
	if cert.Rollover {
		return ROLLING_OVER, 0
	}
	certTTL := float64(cert.NotAfter.Sub(cert.NotBefore).Seconds())
	rolloverTime := cert.NotAfter.Add(time.Duration(certTTL*float64(r.RolloverTimePercentage)/100.0) * time.Second)
	rolloverWindowStart := rolloverTime.Add(-r.RolloverWindow)
	if now.After(rolloverWindowStart) {
		return START_ROLL_OVER, 0
	}
	maxTTL := rolloverWindowStart.Add(rand.N(r.RolloverWindow)).Sub(now)
	return ACTIVE, maxTTL
}

func getRole(ctx context.Context, storage logical.Storage, name string) (*role, error) {

	storageEntry, err := storage.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}

	var d map[string]interface{}
	err = storageEntry.DecodeJSON(&d)
	if err != nil {
		return nil, err
	}

	var r *role
	err = mapstructure.Decode(d, &r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *role) save(ctx context.Context, storage logical.Storage, name string) error {
	var data map[string]interface{}
	err := mapstructure.Decode(r, &data)
	if err != nil {
		return err
	}

	storageEntry, err := logical.StorageEntryJSON(rolePrefix+name, data)
	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
