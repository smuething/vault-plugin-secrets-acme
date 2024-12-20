package acme

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var keyTypes = []interface{}{
	"EC256",
	"EC384",
	"RSA2048",
	"RSA4096",
	"RSA8192",
}

func pathAccount(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: accountPrefix + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.accountList,
				},
			},
		},
		{
			Pattern: accountPrefix + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "The name of thie account",
				},
				"server_url": {
					Type: framework.TypeString,
					// Required is only used in the documentation for now
					Required:    true,
					Description: "The ACME server URL",
				},
				"terms_of_service_agreed": {
					Type:        framework.TypeBool,
					Default:     false,
					Description: "Boolean indicating that you agree to the terms of service of the ACME provider",
				},
				"key_type": {
					Type:          framework.TypeString,
					Default:       "EC256",
					AllowedValues: keyTypes,
					Description:   "[Optional] The private key type to use for the account certificate",
				},
				// TODO(remi): We should have a list of those so we can request certs
				// for domains registred to different providers
				"provider": {
					Type:        framework.TypeString,
					Description: "The name of the LEGO DNS provider",
				},
				"provider_configuration": {
					Type:        framework.TypeKVPairs,
					Description: "Configuration for the DNS provider. Can be supplied multiple times if more than one argument is required.",
				},
				"enable_http_01": {
					Type:        framework.TypeBool,
					Description: "Flag controlling whether the account uses HTTP-01 challenges for authorization",
				},
				"enable_tls_alpn_01": {
					Type:        framework.TypeBool,
					Description: "Flag controlling whether the account uses ALPN-01 challenges for authorization",
				},
				"dns_resolvers": {
					Type:        framework.TypeStringSlice,
					Description: "A list of DNS servers to check for propagation of the DNS challenge",
				},
				"ignore_dns_propagation": {
					Type:        framework.TypeBool,
					Default:     false,
					Description: "A LEGO flag that controls whether LEGO will follow the DNS lookup chain to the authoritative server (I think)",
				},
				"contact": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "The contact email for this account",
				},
				"use_ari": {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Whether to use ARI information to control certificat renewal",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.accountWrite,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.accountRead,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.accountWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.accountDelete,
				},
			},
		},
	}
}

func getKeyType(t string) (certcrypto.KeyType, error) {
	switch t {
	case "EC256":
		return certcrypto.EC256, nil
	case "EC384":
		return certcrypto.EC384, nil
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	default:
		return "", fmt.Errorf("%q is not a supported key type", t)
	}
}

func (b *backend) accountWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	serverURL := data.Get("server_url").(string)
	contact := data.Get("contact").(string)
	termsOfServiceAgreed := data.Get("terms_of_service_agreed").(bool)
	provider := data.Get("provider").(string)
	providerConfiguration := data.Get("provider_configuration").(map[string]string)
	enableHTTP01 := data.Get("enable_http_01").(bool)
	enableTLSALPN01 := data.Get("enable_tls_alpn_01").(bool)
	dnsResolvers := data.Get("dns_resolvers").([]string)
	ignoreDNSPropagation := data.Get("ignore_dns_propagation").(bool)
	useARI := data.Get("use_ari").(bool)

	var update bool
	user, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if user == nil {
		b.Logger().Info("Generating key pair for new account")
		keyType, err := getKeyType(data.Get("key_type").(string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		privateKey, err := certcrypto.GeneratePrivateKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate account key pair: %w", err)
		}

		user = &account{
			ServerURL: serverURL,
			KeyType:   data.Get("key_type").(string),
			Key:       PrivateKey{PrivateKey: privateKey},
		}
	} else {
		update = true
		if serverURL != user.ServerURL {
			return logical.ErrorResponse("Cannot update server_url"), nil
		}
		if data.Get("key_type").(string) != user.KeyType {
			return logical.ErrorResponse("Cannot update key_type"), nil
		}
	}

	user.Email = contact
	user.Provider = provider
	user.ProviderConfiguration = providerConfiguration
	user.EnableHTTP01 = enableHTTP01
	user.EnableTLSALPN01 = enableTLSALPN01
	user.TermsOfServiceAgreed = termsOfServiceAgreed
	user.DNSResolvers = dnsResolvers
	user.IgnoreDNSPropagation = ignoreDNSPropagation
	user.UseARI = useARI

	client, err := user.getClient()
	if err != nil {
		return nil, err
	}

	var reg *registration.Resource
	options := registration.RegisterOptions{
		TermsOfServiceAgreed: termsOfServiceAgreed,
	}
	if update {
		b.Logger().Info("Updating account")
		reg, err = client.Registration.UpdateRegistration(options)
	} else {
		b.Logger().Info("Registring new account")
		reg, err = client.Registration.Register(options)
	}

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	user.Registration = reg

	b.Logger().Info("Saving account")
	if err = user.save(ctx, req.Storage, name, serverURL); err != nil {
		return nil, err
	}

	return b.accountRead(ctx, req, data)
}

func (b *backend) accountRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	a, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	return &logical.Response{Data: ConvertToMapStringAny(a)}, nil
}

func (b *backend) accountDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	a, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	client, err := a.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new client: %w", err)
	}

	if err = client.Registration.DeleteRegistration(); err != nil {
		return nil, fmt.Errorf("failed to deactivate registration: %w", err)
	}

	err = req.Storage.Delete(ctx, req.Path)

	return nil, err
}

func (b *backend) accountList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, accountPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
