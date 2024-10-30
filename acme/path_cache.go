package acme

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCache(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "cache/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.cacheClear,
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.cacheList,
				},
			},
		},
	}
}

func (b *backend) cacheClear(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.cache.Lock()
	defer b.cache.Unlock()
	err := b.cache.Clear(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to clear cache"), err
	}
	return nil, nil
}

func (b *backend) cacheList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.cache.Lock()
	defer b.cache.Unlock()

	keys, err := b.cache.List(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	b.Logger().Debug("Listing cache keys", "keys", keys)

	keyInfo := make(map[string]interface{})
	for _, key := range keys {
		ce, err := b.cache.Read(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if ce == nil {
			continue
		}
		keyInfo[key] = &map[string]interface{}{
			"account":        ce.Account,
			"role":           ce.Role,
			"primary_domain": ce.Domain,
			"domains":        ce.Domains,
			"leases":         ce.Leases,
			"certificates":   len(ce.Certificates),
		}
	}

	return logical.ListResponseWithInfo(keys, keyInfo), nil
}
