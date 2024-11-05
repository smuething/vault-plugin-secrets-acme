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
			"stable_url": {
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
			"cert_id": {
				Type: framework.TypeString,
			},
		},
		Renew:  b.managedCertRenew,
		Revoke: b.managedCertRevoke,
	}
}

func (r *role) getActiveCertID(b *backend, ce *CacheEntry, role *role) (string, string) {
	var active_cert_id = ""
	var rollover_cert_id = ""
	// try to find active certificate
	for cert_id, cc := range ce.Certificates {
		b.Logger().Debug("Looking at certificate", "cert_id", cert_id)
		if role.GetAccount().UseARI {
			_ = cc.UpdateARIInformation(role)
		}
		state, _ := r.CertificateState(cc)
		switch state {
		case ACTIVE:
			if active_cert_id != "" {
				panic("There must never be more than one active certificate for each cache key")
			}
			active_cert_id = cert_id
		case START_ROLL_OVER:
			cc.Rollover = true
			rollover_cert_id = cert_id
		}
	}
	return active_cert_id, rollover_cert_id
}

func (b *backend) buildManagedCertSecret(_ *logical.Request, roleName string, role *role, cacheKey string, cc *CachedCertificate) (*logical.Response, error) {

	state, maxTTL := role.CertificateState(cc)
	if state != ACTIVE {
		return nil, fmt.Errorf("Can only build secret from certificate in state ACTIVE")
	}

	s := b.Secret(secretManagedCertType).Response(
		map[string]interface{}{
			"role":        roleName,
			"domain":      cc.Domain,
			"url":         cc.CertURL,
			"stable_url":  cc.CertStableURL,
			"private_key": string(cc.PrivateKey),
			"cert":        string(cc.Cert),
			"issuer_cert": string(cc.IssuerCertificate),
			"not_before":  cc.NotBefore.String(),
			"not_after":   cc.NotAfter.String(),
			"cert_id":     cc.CertID,
		},
		// this will be used when revoking the certificate
		map[string]interface{}{
			"cache_key": cacheKey,
			"cert_id":   cc.CertID,
		})

	if role.GetAccount().UseARI {

		now := time.Now()

		certTTL := cc.ARIRenewalTime.Sub(now)

		if certTTL <= 0 {
			return nil, fmt.Errorf("Cannot build secret for certificate that needs renewal according to ARI info")
		}

		s.Secret.MaxTTL = certTTL
		s.Secret.TTL = certTTL

		if role.MaxTTL > 0 {
			s.Secret.MaxTTL = min(s.Secret.MaxTTL, role.MaxTTL)
		}

		if role.TTL > 0 {
			s.Secret.TTL = min(s.Secret.TTL, role.TTL)
		}

		timeToNextCheck := cc.ARINextCheck.Sub(now)
		if timeToNextCheck > 0 {
			s.Secret.TTL = min(s.Secret.TTL, timeToNextCheck)
		}

	} else {
		s.Secret.MaxTTL = role.MaxTTL

		if role.TTL > 0 {
			s.Secret.TTL = min(role.TTL, maxTTL)
		} else {
			s.Secret.TTL = maxTTL
		}
	}

	b.Logger().Debug("secret prepared", "TTL", s.Secret.TTL, "MaxTTL", s.Secret.MaxTTL)

	return s, nil
}

func (b *backend) getManagedCertSecret(ctx context.Context, req *logical.Request, data *framework.FieldData, roleName string, role *role, names []string) (*logical.Response, error) {

	policy := data.Get("policy").(string)

	var certID = ""
	if policy != POLICY_REUSE {
		id, ok := data.GetOk("cert_id")
		if !ok {
			return nil, fmt.Errorf("Certificate ID of existing certificate is required for policy '%s'", policy)
		}
		certID = id.(string)
	}

	cacheKey, err := getCacheKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %w", err)
	}

	b.Logger().Debug("Got cacheKey", "cacheKey", cacheKey)

	b.cache.Lock()
	defer b.cache.Unlock()

	ce, err := b.cache.Read(ctx, req.Storage, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("cache error: %w", err)
	}

	var cert *certificate.Resource = nil

	var activeCertID = ""

	if ce == nil {

		b.Logger().Debug("No cache entry, creating one")

		// certificate is not cached, we have to request a new one
		cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, role, names, "")
		if err != nil {
			return nil, err
		}

		ce = b.cache.Create(ctx, req.Storage, roleName, role, cacheKey, cert)

		b.Logger().Debug("cache entry created", "num_certs", len(ce.Certificates), "ce", ce)

		// get the active thumbprint (there is only one)
		for id, cc := range ce.Certificates {
			b.Logger().Debug("certID", "certID", id)
			activeCertID = id
			if role.GetAccount().UseARI {
				if err = cc.UpdateARIInformation(role); err != nil {
					return nil, err
				}
			}
		}
	} else {

		b.Logger().Debug("Found cache entry")

		switch policy {
		case POLICY_REUSE:
			activeCertID, certID = role.getActiveCertID(b, ce, role)
		case POLICY_ROLLOVER:
			// set the old certificate to roll over (if we still have it)
			cc := ce.Certificates[certID]
			if cc != nil {
				cc.Rollover = true
			}
			activeCertID, _ = role.getActiveCertID(b, ce, role)
			b.Logger().Debug("Search for activeCertID complete", "activeCertID", activeCertID)
		case POLICY_ROLLOVER_REVOKE:
			// set the old certificate to roll over (if we still have it) and also enable
			// revocaction on expiry
			cc := ce.Certificates[activeCertID]
			if cc != nil {
				cc.Rollover = true
				cc.RevokeOnEviction = true
			}
			activeCertID, _ = role.getActiveCertID(b, ce, role)
			b.Logger().Debug("Search for activeCertID complete", "activeCertID", activeCertID)
		case POLICY_REVOKE:
			cc := ce.Certificates[certID]
			if cc != nil {
				client, err := role.GetAccount().getClient()
				if err != nil {
					return nil, err
				}
				if cc.Rollover {
					// the certificate is already rolling over, no need to request a new one
					// we can just go ahead and revoke the old certificate
					if err := client.Certificate.Revoke(cc.Cert); err != nil {
						return nil, err
					}
					activeCertID, _ = role.getActiveCertID(b, ce, role)
				} else {
					// first, get a new certificate
					oldCertID := ""
					if role.GetAccount().UseARI {
						oldCertID = certID
					}
					cert, err := getCertFromACMEProvider(ctx, b.Logger(), req, role, names, oldCertID)
					if err != nil {
						return nil, err
					}

					// now, revoke the old certificate ...
					if err = client.Certificate.Revoke(cc.Cert); err != nil {
						return nil, err
					}

					// ... remove from cache ...
					delete(ce.Certificates, certID)

					// and save the changes *before* adding the new certificate to the store
					// otherwise, an error later on would create orphaned cache entries
					if err = ce.Save(ctx, req.Storage, cacheKey); err != nil {
						return nil, err
					}

					certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
					if err != nil {
						return nil, err
					}

					activeCertID = GetCertID(certs[0])

					ce.Certificates[activeCertID] = &CachedCertificate{
						Leases:            0,
						Domain:            certs[0].Subject.CommonName,
						CertURL:           cert.CertURL,
						CertStableURL:     cert.CertStableURL,
						PrivateKey:        cert.PrivateKey,
						Cert:              cert.Certificate,
						IssuerCertificate: cert.IssuerCertificate,
						CSR:               cert.CSR,
						NotBefore:         certs[0].NotBefore,
						NotAfter:          certs[0].NotAfter,
						RevokeOnEviction:  role.RevokeOnExpiry,
						Rollover:          false,
						CertID:            activeCertID,
					}

					if role.GetAccount().UseARI {
						if err = ce.Certificates[activeCertID].UpdateARIInformation(role); err != nil {
							return nil, err
						}
					}

				}
			}
		}

		if activeCertID == "" {
			// we have no certificate, we either need to get a new one or renew an existing certificate
			cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, role, names, certID)
			if err != nil {
				return nil, err
			}

			certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
			if err != nil {
				return nil, err
			}
			activeCertID = GetCertID(certs[0])

			ce.Certificates[activeCertID] = &CachedCertificate{
				Leases:            0,
				Domain:            certs[0].Subject.CommonName,
				CertURL:           cert.CertURL,
				CertStableURL:     cert.CertStableURL,
				PrivateKey:        cert.PrivateKey,
				Cert:              cert.Certificate,
				IssuerCertificate: cert.IssuerCertificate,
				CSR:               cert.CSR,
				NotBefore:         certs[0].NotBefore,
				NotAfter:          certs[0].NotAfter,
				RevokeOnEviction:  role.RevokeOnExpiry,
				Rollover:          false,
				CertID:            activeCertID,
			}

		}

		// increase lease counts
		ce.Certificates[activeCertID].Leases++
		ce.Leases++

	}

	b.Logger().Debug("Preparing secret", "activeCertID", activeCertID, "certID", certID)

	secretResponse, err := b.buildManagedCertSecret(req, roleName, role, cacheKey, ce.Certificates[activeCertID])
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
	b.cache.Lock()
	defer b.cache.Unlock()
	resp := &logical.Response{Secret: req.Secret}

	cacheKey := req.Secret.InternalData["cache_key"].(string)
	certID := req.Secret.InternalData["cert_id"].(string)

	ce, err := b.cache.Read(ctx, req.Storage, cacheKey)
	if err != nil {
		return nil, err
	}
	if ce == nil {
		return nil, fmt.Errorf("secret data not found in cache, request a new one")
	}

	role, err := getRole(ctx, req.Storage, ce.Role)
	if err != nil {
		return nil, err
	}

	cc, ok := ce.Certificates[certID]
	if !ok {
		return nil, fmt.Errorf("certificate not found")
	}

	if cc.Rollover {
		// certificate rollover already started
		return nil, fmt.Errorf("certificate rollover")
	}

	state, ttl := role.CertificateState(cc)
	if state != ACTIVE {
		// we are in the rollover window, client must request a new certificate
		return nil, fmt.Errorf("certificate rollover")
	}

	if req.Secret.TTL > 0 {
		ttl = min(ttl, req.Secret.TTL)
	}

	if role.TTL > 0 {
		ttl = min(ttl, role.TTL)
	}

	resp.Secret.TTL = ttl

	return resp, nil
}

func (ce *CacheEntry) revokeCachedCertificate(ctx context.Context, req *logical.Request, certID string) error {

	cc, ok := ce.Certificates[certID]
	if !ok {
		return fmt.Errorf("certificate ID not found in cache entry")
	}

	if cc.NotAfter.Add(5 * time.Minute).After(time.Now()) {
		// just silently ignore the request, no point in spamming the CRLs
		return nil
	}

	r, err := getRole(ctx, req.Storage, ce.Role)
	if err != nil {
		return err
	}

	a, err := getAccount(ctx, req.Storage, r.Account)
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
	certID := req.Secret.InternalData["cert_id"].(string)

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
	cc, ok := ce.Certificates[certID]
	if !ok {
		// revocationError = fmt.Errorf("Certificate not found in cache")
	} else {

		cc.Leases--
		if cc.Leases == 0 {
			// revoke certificate if requested
			if cc.RevokeOnEviction {
				revocationError = ce.revokeCachedCertificate(ctx, req, certID)
			}
			// remove cache entry
			delete(ce.Certificates, certID)
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
