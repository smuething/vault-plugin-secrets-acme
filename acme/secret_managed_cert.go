package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secretManagedCert(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretManagedCertType,
		Fields: map[string]*framework.FieldSchema{
			"domain": {
				Type: framework.TypeString,
			},
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
		Renew:  b.managedCertRenew,
		Revoke: b.managedCertRevoke,
	}
}

func (r *role) getActiveCertificateSerial(b *backend, ce *CacheEntry) (string, string) {
	var active_serial = ""
	var rollover_serial = ""
	// try to find active certificate
	for s, cc := range ce.Certificates {
		b.Logger().Debug("Looking at certificate", "serial", s, "rollover", cc.Rollover, "rolloverAfter", cc.RolloverAfter)
		if cc.Rollover {
			continue
		}
		if cc.RolloverAfter.Add(-r.RolloverWindow).Before(time.Now()) {
			// set this certificate to roll over and return its serial (for renewal)
			cc.Rollover = true
			rollover_serial = s
			continue
		}
		if active_serial != "" {
			panic("foo")
		}
		active_serial = s
	}
	return active_serial, rollover_serial
}

func (b *backend) buildManagedCertSecret(_ *logical.Request, roleName string, role *role, cacheKey string, cc *CachedCertificate) (*logical.Response, error) {

	certs, err := certcrypto.ParsePEMBundle(cc.Cert)
	if err != nil {
		return nil, err
	}

	notBefore := certs[0].NotBefore
	notAfter := certs[0].NotAfter

	s := b.Secret(secretManagedCertType).Response(
		map[string]interface{}{
			"role":        roleName,
			"domain":      cc.Domain,
			"url":         cc.CertURL,
			"stable_url":  cc.CertStableURL,
			"private_key": string(cc.PrivateKey),
			"cert":        string(cc.Cert),
			"issuer_cert": string(cc.IssuerCertificate),
			"not_before":  notBefore.String(),
			"not_after":   notAfter.String(),
		},
		// this will be used when revoking the certificate
		map[string]interface{}{
			"cache_key": cacheKey,
			"serial":    certs[0].SerialNumber.String(),
		})

	s.Secret.MaxTTL = max(0, time.Until(cc.RolloverAfter))

	if role.MaxTTL > 0 {
		s.Secret.MaxTTL = min(s.Secret.MaxTTL, role.MaxTTL)
	}

	s.Secret.TTL = s.Secret.MaxTTL

	if role.TTL > 0 {
		s.Secret.TTL = min(
			s.Secret.TTL,
			s.Secret.MaxTTL,
			role.TTL,
		)

		s.Secret.Increment = role.TTL
	}

	b.Logger().Warn("secret prepared", "TTL", s.Secret.TTL, "MaxTTL", s.Secret.MaxTTL)

	return s, nil
}

func (b *backend) getManagedCertSecret(ctx context.Context, req *logical.Request, data *framework.FieldData, roleName string, role *role, names []string) (*logical.Response, error) {

	policy := data.Get("policy").(string)

	var serial = ""
	if policy != POLICY_REUSE {
		s, ok := data.GetOk("serial")
		if !ok {
			return nil, fmt.Errorf("serial of existing certificate is required for policy '%s'", policy)
		}
		serial = s.(string)
	}

	cacheKey, err := getCacheKey(role, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %w", err)
	}

	b.Logger().Warn("Got cachekey", "cacheKey", cacheKey)

	b.cache.Lock()
	defer b.cache.Unlock()

	ce, err := b.cache.Read(ctx, req.Storage, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("cache error: %w", err)
	}

	var cert *certificate.Resource = nil

	var active_serial = ""

	if ce == nil {

		b.Logger().Warn("No cache entry, creating one")

		// certificate is not cached, we have to request a new one
		cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, role, names)
		if err != nil {
			return nil, err
		}

		ce = b.cache.Create(ctx, req.Storage, roleName, role, cacheKey, cert)

		b.Logger().Warn("cache entry created", "num_certs", len(ce.Certificates), "ce", ce)

		// get the active serial (there is only one)
		for s := range ce.Certificates {
			b.Logger().Warn("serial", "s", s)
			active_serial = s
		}
	} else {

		b.Logger().Warn("Found cache entry")

		switch policy {
		case POLICY_REUSE:
			active_serial, serial = role.getActiveCertificateSerial(b, ce)
		case POLICY_ROLLOVER:
			// set the old certificate to roll over (if we still have it)
			cc := ce.Certificates[serial]
			if cc != nil {
				cc.Rollover = true
			}
			active_serial, _ = role.getActiveCertificateSerial(b, ce)
			b.Logger().Warn("Search for active_serial complete", "active_serial", active_serial)
		case POLICY_ROLLOVER_REVOKE:
			// set the old certificate to roll over (if we still have it) and also enable
			// revocaction on expiry
			cc := ce.Certificates[serial]
			if cc != nil {
				cc.Rollover = true
				cc.RevokeOnEviction = true
			}
			active_serial, _ = role.getActiveCertificateSerial(b, ce)
			b.Logger().Warn("Search for active_serial complete", "active_serial", active_serial)
		case POLICY_REVOKE:
			cc := ce.Certificates[serial]
			if cc != nil {
				a, err := getAccount(ctx, req.Storage, accountPrefix+role.Account)
				if err != nil {
					return nil, err
				}
				client, err := a.getClient()
				if err != nil {
					return nil, err
				}
				if cc.Rollover {
					// the certificate is already rolling over, no need to request a new one
					// we can just go ahead and revoke the old certificate
					if err := client.Certificate.Revoke(cc.Cert); err != nil {
						return nil, err
					}
					active_serial, _ = role.getActiveCertificateSerial(b, ce)
				} else {
					// first, get a new certificate
					cert, err := client.Certificate.RenewWithOptions(*cc.Certificate(), &certificate.RenewOptions{Bundle: true})
					if err != nil {
						return nil, err
					}

					// now, revoke the old certificate ...
					if err = client.Certificate.Revoke(cc.Cert); err != nil {
						return nil, err
					}

					// ... remove from cache ...
					delete(ce.Certificates, serial)

					// and save the changes *before* adding the new certificate to the store
					// otherwise, an error later on would create orphaned cache entries
					if err = ce.Save(ctx, req.Storage, cacheKey); err != nil {
						return nil, err
					}

					certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
					if err != nil {
						return nil, err
					}
					active_serial = certs[0].SerialNumber.String()

					ce.Certificates[active_serial] = &CachedCertificate{
						Leases:            0,
						Domain:            certs[0].Subject.CommonName,
						CertURL:           cert.CertURL,
						CertStableURL:     cert.CertStableURL,
						PrivateKey:        cert.PrivateKey,
						Cert:              cert.Certificate,
						IssuerCertificate: cert.IssuerCertificate,
						CSR:               cert.CSR,
						NotAfter:          certs[0].NotAfter,
						RolloverAfter:     role.RolloverAfter(certs[0]),
						RevokeOnEviction:  role.RevokeOnExpiry,
						Rollover:          false,
					}

				}
			}
		}

		if active_serial == "" {
			// we have no certificate, we either need to get a new one or renew an existing certificate
			if cc, ok := ce.Certificates[serial]; ok {
				a, err := getAccount(ctx, req.Storage, accountPrefix+role.Account)
				if err != nil {
					return nil, err
				}
				client, err := a.getClient()
				if err != nil {
					return nil, err
				}
				cert, err = client.Certificate.RenewWithOptions(*cc.Certificate(), &certificate.RenewOptions{Bundle: true})
				if err != nil {
					return nil, err
				}
			} else {
				cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, role, names)
				if err != nil {
					return nil, err
				}
			}

			certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
			if err != nil {
				return nil, err
			}
			active_serial = certs[0].SerialNumber.String()

			ce.Certificates[active_serial] = &CachedCertificate{
				Leases:            0,
				Domain:            certs[0].Subject.CommonName,
				CertURL:           cert.CertURL,
				CertStableURL:     cert.CertStableURL,
				PrivateKey:        cert.PrivateKey,
				Cert:              cert.Certificate,
				IssuerCertificate: cert.IssuerCertificate,
				CSR:               cert.CSR,
				NotAfter:          certs[0].NotAfter,
				RolloverAfter:     role.RolloverAfter(certs[0]),
				RevokeOnEviction:  role.RevokeOnExpiry,
				Rollover:          false,
			}

		}

		// increase lease counts
		ce.Certificates[active_serial].Leases++
		ce.Leases++

	}

	b.Logger().Warn("Preparing secret", "active_serial", active_serial, "serial", serial)

	secretResponse, err := b.buildManagedCertSecret(req, roleName, role, cacheKey, ce.Certificates[active_serial])
	if err != nil {
		return nil, err
	}

	// this has to happen as the last step, to avoid erroneous updates of the cache
	if err = ce.Save(ctx, req.Storage, cacheKey); err != nil {
		return nil, err
	}

	return secretResponse, nil
}

func (b *backend) managedCertRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	b.cache.Lock()
	defer b.cache.Unlock()

	cacheKey := req.Secret.InternalData["cache_key"].(string)
	serial := req.Secret.InternalData["serial"].(string)

	ce, err := b.cache.Read(ctx, req.Storage, cacheKey)
	if err != nil {
		return nil, err
	}

	role, err := getRole(ctx, req.Storage, rolePrefix+ce.Role)
	if err != nil {
		return nil, err
	}

	cc, ok := ce.Certificates[serial]
	if !ok {
		return nil, fmt.Errorf("certificate not found")
	}

	if cc.Rollover {
		// someone manually initiated a certificate rollover
		return nil, fmt.Errorf("certificate rollover")
	}

	if cc.RolloverAfter.Before(time.Now().Add(-role.RolloverWindow)) {
		// we are in the rollover window, client must request a new certificate
		return nil, fmt.Errorf("certificate rollover")
	}

	// Increment TTL by the minimum of the requested duration, the duration specified in the role,
	// the max TTL specified in the role and the rollover time of the certificate
	resp.Secret.TTL = min(
		req.Secret.Increment,
		max(0, time.Until(cc.RolloverAfter)),
	)

	if role.TTL > 0 {
		resp.Secret.TTL = min(resp.Secret.TTL, role.TTL)
	}

	if role.MaxTTL > 0 {
		resp.Secret.TTL = min(resp.Secret.TTL, max(0, time.Until(req.Secret.IssueTime.Add(role.MaxTTL))))
	}

	return resp, nil
}

func (ce *CacheEntry) revokeCachedCertificate(ctx context.Context, req *logical.Request, serial string) error {

	cc, ok := ce.Certificates[serial]
	if !ok {
		return fmt.Errorf("serial not found in cache entry")
	}

	if cc.NotAfter.Add(5 * time.Minute).After(time.Now()) {
		// just silently ignore the request, no point in spamming the CRLs
		return nil
	}

	r, err := getRole(ctx, req.Storage, rolePrefix+ce.Role)
	if err != nil {
		return err
	}

	a, err := getAccount(ctx, req.Storage, accountPrefix+r.Account)
	if err != nil {
		return err
	}

	client, err := a.getClient()
	if err != nil {
		return err
	}

	return client.Certificate.Revoke(cc.Cert)
}

func (b *backend) managedCertRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.cache.Lock()
	defer b.cache.Unlock()
	cacheKey := req.Secret.InternalData["cache_key"].(string)
	serial := req.Secret.InternalData["serial"].(string)

	ce, err := b.cache.Read(ctx, req.Storage, cacheKey)
	if err != nil {
		return nil, err
	}
	if ce == nil {
		return nil, nil
	}

	var revocationError error
	var cacheError error

	// first, handle the certificate
	cc, ok := ce.Certificates[serial]
	if !ok {
		// revocationError = fmt.Errorf("Certificate not found in cache")
	} else {

		cc.Leases--
		if cc.Leases == 0 {
			// revoke certificate if requested
			if cc.RevokeOnEviction {
				revocationError = ce.revokeCachedCertificate(ctx, req, serial)
			}
			// remove cache entry
			delete(ce.Certificates, serial)
		}
	}

	ce.Leases--

	if ce.Leases == 0 {
		// sanity check, without any leases on the cache entry there also shouldn't be any certificates left
		// if len(ce.Certificates) > 0 {
		// 	panic("Inconsistent plugin data state: cache entry without leases still has active certificates")
		// }
		// evict cache key
		cacheError = b.cache.Delete(ctx, req.Storage, cacheKey)
	} else {
		cacheError = ce.Save(ctx, req.Storage, cacheKey)
	}

	if revocationError != nil || cacheError != nil {
		if revocationError == nil {
			return nil, cacheError
		} else if cacheError == nil {
			return nil, revocationError
		} else {
			return nil, fmt.Errorf("revocation error: %w, cache error: %w", revocationError, cacheError)
		}
	}

	return nil, nil
}
