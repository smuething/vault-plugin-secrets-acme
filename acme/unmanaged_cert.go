package acme

import (
	"context"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) getUnmanagedCert(ctx context.Context, req *logical.Request, roleName string, role *role, names []string) (*logical.Response, error) {

	// No ARI support here
	cert, err := getCertFromACMEProvider(ctx, b.Logger(), req, role, names, "")
	if err != nil {
		return logical.ErrorResponse("Failed to validate certificate signing request: %s", err), err
	}

	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return nil, err
	}

	notBefore := certs[0].NotBefore
	notAfter := certs[0].NotAfter
	ttl := time.Until(notAfter)

	return &logical.Response{
		Data: map[string]any{
			"role":        roleName,
			"url":         cert.CertURL,
			"private_key": string(cert.PrivateKey),
			"cert":        string(cert.Certificate),
			"issuer_cert": string(cert.IssuerCertificate),
			"not_before":  notBefore.String(),
			"not_after":   notAfter.String(),
			"ttl":         ttl.String(),
			"max_ttl":     ttl.String(),
		},
	}, nil

}
