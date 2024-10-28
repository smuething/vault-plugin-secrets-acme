package acme

import (
	"context"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secretUnmanagedCert(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretUnmanagedCertType,
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type: framework.TypeString,
			},
			"private_key": {
				Type: framework.TypeString,
			},
			"cert": {
				Type: framework.TypeString,
			},
			"issuer_cert": {
				Type: framework.TypeString,
			},
			"not_before": {
				Type: framework.TypeString,
			},
			"not_after": {
				Type: framework.TypeString,
			},
			"role": {
				Type: framework.TypeString,
			},
		},
		Revoke: b.unmanagedCertRevoke,
	}
}

func (b *backend) unmanagedCertRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (b *backend) getUnmanagedCertSecret(ctx context.Context, req *logical.Request, roleName string, role *role, names []string) (*logical.Response, error) {

	cert, err := getCertFromACMEProvider(ctx, b.Logger(), req, role, names)
	if err != nil {
		return logical.ErrorResponse("Failed to validate certificate signing request: %s", err), err
	}

	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return nil, err
	}

	notBefore := certs[0].NotBefore
	notAfter := certs[0].NotAfter

	s := b.Secret(secretUnmanagedCertType).Response(
		map[string]interface{}{
			"role":        roleName,
			"url":         cert.CertURL,
			"private_key": string(cert.PrivateKey),
			"cert":        string(cert.Certificate),
			"issuer_cert": string(cert.IssuerCertificate),
			"not_before":  notBefore.String(),
			"not_after":   notAfter.String(),
		},
		nil,
	)

	// return a static secret
	s.Secret.TTL = 0
	s.Secret.MaxTTL = 0

	return s, nil
}
