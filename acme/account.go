package acme

import (
	"context"
	"crypto"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/logical"
)

type account struct {
	Email                 string                 `json:"email,omitempty"`
	Registration          *registration.Resource `json:"registration,omitempty"`
	Key                   PrivateKey             `json:"key,omitempty"`
	KeyType               string                 `json:"key_type,omitempty"`
	ServerURL             string                 `json:"server_url,omitempty"`
	Provider              string                 `json:"provider,omitempty"`
	ProviderConfiguration map[string]string      `json:"provider_configuration,omitempty"`
	EnableHTTP01          bool                   `json:"enable_http_01,omitempty"`
	EnableTLSALPN01       bool                   `json:"enable_tlsalpn_01,omitempty"`
	TermsOfServiceAgreed  bool                   `json:"terms_of_service_agreed,omitempty"`
	DNSResolvers          []string               `json:"dns_resolvers,omitempty"`
	IgnoreDNSPropagation  bool                   `json:"ignore_dns_propagation,omitempty"`
	UseARI                bool                   `json:"use_ari"`
}

// GetEmail returns the Email of the user
func (a *account) GetEmail() string {
	return a.Email
}

// GetRegistration returns the Email of the user
func (a *account) GetRegistration() *registration.Resource {
	return a.Registration
}

// GetPrivateKey returns the private key of the user
func (a *account) GetPrivateKey() crypto.PrivateKey {
	return a.Key.PrivateKey
}

func (a *account) getClient() (*lego.Client, error) {
	config := lego.NewConfig(a)
	config.CADirURL = a.ServerURL

	return lego.NewClient(config)
}

func getAccount(ctx context.Context, storage logical.Storage, name string) (*account, error) {
	storageEntry, err := storage.Get(ctx, accountPrefix+name)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}
	a := &account{}
	if err = storageEntry.DecodeJSON(a); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *account) save(ctx context.Context, storage logical.Storage, name string, serverURL string) error {

	storageEntry, err := logical.StorageEntryJSON(accountPrefix+name, a)

	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
