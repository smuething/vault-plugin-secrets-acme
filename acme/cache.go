package acme

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
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
	Leases            int
	Domain            string
	CertURL           string
	CertStableURL     string
	PrivateKey        []byte
	Cert              []byte
	IssuerCertificate []byte
	CSR               []byte
	NotAfter          time.Time
	RolloverAfter     time.Time
	RevokeOnEviction  bool
	Rollover          bool
}

type CacheEntry struct {
	Leases  int
	Account string
	Role    string
	Domain  string
	Domains []string

	// cached certificates, indexed by the certificate serial number
	Certificates map[string]*CachedCertificate
}

func NewCacheEntry(role_name string, role *role, cert *certificate.Resource) *CacheEntry {

	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		panic("Invalid certificate")
	}

	return &CacheEntry{
		Leases:  1,
		Account: role.Account,
		Role:    role_name,
		Domain:  cert.Domain,
		Domains: certs[0].DNSNames,
		Certificates: map[string]*CachedCertificate{
			certs[0].SerialNumber.String(): {
				Leases:            1,
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
	storageEntry, err := logical.StorageEntryJSON(key, ce)
	if err != nil {
		return fmt.Errorf("failed to create cache entry: %v", err)
	}
	return storage.Put(ctx, storageEntry)
}

func (c *Cache) List(ctx context.Context, storage logical.Storage) ([]string, error) {
	return storage.List(ctx, cachePrefix)
}

func (c *Cache) Create(ctx context.Context, storage logical.Storage, role_name string, role *role, key string, cert *certificate.Resource) *CacheEntry {
	return NewCacheEntry(role_name, role, cert)
}

func (c *Cache) Read(ctx context.Context, storage logical.Storage, key string) (*CacheEntry, error) {
	storageEntry, err := storage.Get(ctx, key)
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
	return storage.Delete(ctx, key)
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
