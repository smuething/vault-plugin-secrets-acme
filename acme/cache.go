package acme

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Cache struct {
	*sync.Mutex
}

func NewCache() *Cache {
	return &Cache{
		&sync.Mutex{},
	}
}

type CachedCertificate struct {
	Leases            int         `json:"leases"`
	Domain            string      `json:"domain"`
	CertURL           string      `json:"cert_url,omitempty"`
	CertStableURL     string      `json:"cert_stable_url,omitempty"`
	PrivateKey        []byte      `json:"private_key,omitempty"`
	Cert              []byte      `json:"cert,omitempty"`
	IssuerCertificate []byte      `json:"issuer_certificate,omitempty"`
	CSR               []byte      `json:"csr,omitempty"`
	NotBefore         time.Time   `json:"not_before,omitempty"`
	NotAfter          time.Time   `json:"not_after,omitempty"`
	RevokeOnEviction  bool        `json:"revoke_on_eviction,omitempty"`
	Rollover          bool        `json:"rollover,omitempty"`
	CertID            string      `json:"cert_id"`
	ARINextCheck      time.Time   `json:"ari_next_check,omitempty"`
	ARIRenewalWindow  acme.Window `json:"ari_renewal_window,omitempty"`
	ARIRenewalTime    time.Time   `json:"ari_renewal_time,omitempty"`
	ARIExplanationURL string      `json:"ari_explanation_url,omitempty"`
}

type CacheEntry struct {
	Leases  int      `json:"leases"`
	Account string   `json:"account"`
	Role    string   `json:"role"`
	Domain  string   `json:"domain"`
	Domains []string `json:"domains"`

	// cached certificates, indexed by the certificate serial number
	Certificates map[string]*CachedCertificate `json:"certificates"`
}

func (cc *CachedCertificate) UpdateARIInformation(role *role) error {
	if !role.GetAccount().UseARI {
		return fmt.Errorf("Acount does not use ARI")
	}

	now := time.Now()

	if cc.ARINextCheck.After(now.Add(role.TTL)) {
		// no need to renew ARI information
		return nil
	}

	certs, err := certcrypto.ParsePEMBundle(cc.Cert)
	if err != nil {
		panic("Invalid certificate")
	}

	client, err := role.GetAccount().getClient()
	if err != nil {
		return err
	}

	renewalInfo, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: certs[0]})
	if err != nil {
		return err
	}

	cc.ARIRenewalWindow = renewalInfo.SuggestedWindow
	cc.ARINextCheck = now.Add(renewalInfo.RetryAfter)
	cc.ARIExplanationURL = renewalInfo.ExplanationURL

	// The following algorithm is copied from lego/renewal and modified to handle the "renew immediately case"

	// Explicitly convert all times to UTC.
	now = now.UTC()
	start := renewalInfo.SuggestedWindow.Start.UTC()
	end := renewalInfo.SuggestedWindow.End.UTC()

	// Select a uniform random time within the suggested window.
	rt := start
	if window := end.Sub(start); window > 0 {
		randomDuration := time.Duration(rand.Int64N(int64(window)))
		rt = rt.Add(randomDuration)
	}

	// If the selected time is in the past, attempt renewal immediately.
	if rt.Before(now) {
		cc.ARIRenewalTime = now
	}

	// Otherwise, if the client can schedule itself to attempt renewal at exactly the selected time, do so.
	willingToSleepUntil := now.Add(role.TTL)
	if willingToSleepUntil.After(rt) || willingToSleepUntil.Equal(rt) {
		cc.ARIRenewalTime = rt
	}

	// Otherwise, if the selected time is before the next time that the client would wake up normally, attempt renewal immediately.
	if rt.Before(now.Add(role.TTL)) {
		cc.ARIRenewalTime = now
	}

	// Otherwise, sleep until the next normal wake time, re-check ARI, and return to Step 1.
	cc.ARIRenewalTime = rt

	return nil
}

func NewCacheEntry(role_name string, role *role, cert *certificate.Resource) *CacheEntry {

	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		panic("Invalid certificate")
	}

	certID := GetCertID(certs[0])

	return &CacheEntry{
		Leases:  1,
		Account: role.Account,
		Role:    role_name,
		Domain:  cert.Domain,
		Domains: certs[0].DNSNames,
		Certificates: map[string]*CachedCertificate{
			certID: {
				Leases:            1,
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
				CertID:            certID,
			},
		},
	}
}

func (cc *CachedCertificate) Certificate() *certificate.Resource {
	return &certificate.Resource{
		Domain:            cc.Domain,
		CertURL:           cc.CertURL,
		CertStableURL:     cc.CertStableURL,
		PrivateKey:        cc.PrivateKey,
		Certificate:       cc.Cert,
		IssuerCertificate: cc.IssuerCertificate,
		CSR:               cc.CSR,
	}
}

func (ce *CacheEntry) Save(ctx context.Context, storage logical.Storage, key string) error {
	storageEntry, err := logical.StorageEntryJSON(cachePrefix+key, ce)
	if err != nil {
		return fmt.Errorf("failed to create cache entry: %v", err)
	}
	return storage.Put(ctx, storageEntry)
}

func (c *Cache) List(ctx context.Context, storage logical.Storage) ([]string, error) {
	list, err := storage.List(ctx, cachePrefix)
	if err != nil {
		return nil, err
	}
	return list, nil
}

func (c *Cache) Create(ctx context.Context, storage logical.Storage, role_name string, role *role, key string, cert *certificate.Resource) *CacheEntry {
	return NewCacheEntry(role_name, role, cert)
}

func (c *Cache) Read(ctx context.Context, storage logical.Storage, key string) (*CacheEntry, error) {
	storageEntry, err := storage.Get(ctx, cachePrefix+key)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}

	// Something was found in the cache
	ce := &CacheEntry{}
	err = storageEntry.DecodeJSON(ce)
	if err != nil {
		return nil, err
	}

	return ce, nil
}

func (c *Cache) Delete(ctx context.Context, storage logical.Storage, key string) error {
	return storage.Delete(ctx, cachePrefix+key)
}

func (c *Cache) Clear(ctx context.Context, storage logical.Storage) error {
	keys, err := c.List(ctx, storage)
	if err != nil {
		return err
	}

	for _, key := range keys {
		err = c.Delete(ctx, storage, cachePrefix+key)
		if err != nil {
			return err
		}
	}

	return nil
}

func getCacheKey(data *framework.FieldData) (string, error) {

	// only these two fields are actually relevant for discerning different cache entries
	domains, err := getNames(data)
	if err != nil {
		return "", err
	}

	domainListString, err := json.Marshal(domains)
	if err != nil {
		return "", fmt.Errorf("failed to marshall data: %v", err)
	}

	key := data.Get("role").(string) + string(domainListString)
	hashedKey := sha256.Sum256([]byte(key))

	return fmt.Sprintf("%064x", hashedKey), nil
}
