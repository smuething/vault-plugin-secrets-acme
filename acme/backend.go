package acme

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const cachePrefix = "cache/"
const rolePrefix = "role/"
const accountPrefix = "account/"
const certPrefix = "cert/"
const secretManagedCertType = "managed-cert"

type backend struct {
	*framework.Backend
	cache *Cache
}

// Factory creates a new ACME backend implementing logical.Backend
func Factory(version string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := backend{
			cache: NewCache(),
		}

		b.Backend = &framework.Backend{
			BackendType: logical.TypeLogical,
			Secrets: []*framework.Secret{
				secretManagedCert(&b),
			},
			Paths: framework.PathAppend(
				pathAccount(&b),
				pathRole(&b),
				pathCert(&b),
				pathChallenges(&b),
				pathCache(&b),
			),
		}

		b.Logger()

		if version != "" {
			b.Backend.RunningVersion = fmt.Sprintf("v%s", version)
		}

		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}

		return b, nil
	}
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	b.Logger().Debug("Checking path existence", "req.Path", req.Path)
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}
