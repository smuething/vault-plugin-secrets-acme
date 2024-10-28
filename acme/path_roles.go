package acme

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
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
			Pattern: "roles/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:     framework.TypeString,
					Required: true,
				},
				"account": {
					Type:     framework.TypeString,
					Required: true,
				},
				"allowed_domains": {
					Type: framework.TypeCommaStringSlice,
				},
				"allow_bare_domains": {
					Type: framework.TypeBool,
				},
				"allow_subdomains": {
					Type: framework.TypeBool,
				},
				"managed": {
					Type:    framework.TypeBool,
					Default: true,
				},
				"rollover_time_percentage": {
					Type:    framework.TypeInt,
					Default: 70,
				},
				"rollover_window": {
					Type: framework.TypeDurationSecond,
				},
				"key_type": {
					Type:          framework.TypeString,
					AllowedValues: keyTypes,
				},
				"revoke_on_expiry": {
					Type: framework.TypeBool,
				},
				"max_ttl": {
					Type: framework.TypeDurationSecond,
				},
				"ttl": {
					Type: framework.TypeDurationSecond,
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
	if err := r.save(ctx, req.Storage, req.Path); err != nil {
		return nil, err
	}

	b.Logger().Info("reading role")
	return b.roleRead(ctx, req, data)
}

func (b *backend) roleRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Retrieving role from storage")
	r, err := getRole(ctx, req.Storage, req.Path)
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
			"rollover_window":          int64(r.RolloverWindow.Seconds()),
			"key_type":                 r.KeyType,
			"revoke_on_expiry":         r.RevokeOnExpiry,
			"max_ttl":                  int64(r.MaxTTL.Seconds()),
			"ttl":                      int64(r.TTL.Seconds()),
		},
	}, nil
}

func (b *backend) roleDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, req.Path)
}

func (b *backend) roleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

type role struct {
	Account                string
	AllowedDomains         []string
	AllowBareDomains       bool
	AllowSubdomains        bool
	Managed                bool
	RolloverTimePercentage int
	RolloverWindow         time.Duration
	KeyType                string
	RevokeOnExpiry         bool
	MaxTTL                 time.Duration
	TTL                    time.Duration
}

func (r *role) RolloverAfter(cert *x509.Certificate) time.Time {
	certTTL := float64(cert.NotAfter.Sub(cert.NotBefore))
	return cert.NotBefore.Add(time.Duration(certTTL * float64(r.RolloverTimePercentage) / 100.0))
}

func getRole(ctx context.Context, storage logical.Storage, path string) (*role, error) {
	storageEntry, err := storage.Get(ctx, path)
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

func (r *role) save(ctx context.Context, storage logical.Storage, path string) error {
	var data map[string]interface{}
	err := mapstructure.Decode(r, &data)
	if err != nil {
		return err
	}

	storageEntry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
