package acme

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
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
	Leases            int       `json:"leases"`
	Domain            string    `json:"domain"`
	CertURL           string    `json:"cert_url,omitempty"`
	CertStableURL     string    `json:"cert_stable_url,omitempty"`
	PrivateKey        []byte    `json:"private_key,omitempty"`
	Cert              []byte    `json:"cert,omitempty"`
	IssuerCertificate []byte    `json:"issuer_certificate,omitempty"`
	CSR               []byte    `json:"csr,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	RevokeOnEviction  bool      `json:"revoke_on_eviction,omitempty"`
	Rollover          bool      `json:"rollover,omitempty"`
	Thumbprint        string    `json:"thumbprint"`
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

func NewCacheEntry(role_name string, role *role, cert *certificate.Resource) *CacheEntry {

	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		panic("Invalid certificate")
	}

	thumbprint := GetSHA256Thumbprint(certs[0])

	return &CacheEntry{
		Leases:  1,
		Account: role.Account,
		Role:    role_name,
		Domain:  cert.Domain,
		Domains: certs[0].DNSNames,
		Certificates: map[string]*CachedCertificate{
			thumbprint: {
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
				Thumbprint:        thumbprint,
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
	storageList, err := storage.List(ctx, cachePrefix)
	if err != nil {
		return nil, err
	}
	list := make([]string, len(storageList))
	for i, path := range storageList {
		list[i], _ = strings.CutPrefix(path, cachePrefix)
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

func getCacheKey(rolePath string, data *framework.FieldData) (string, error) {

	d := make(map[string]interface{})
	for key := range data.Schema {
		d[key] = data.Get(key)
	}
	dataPath, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("failed to marshall data: %v", err)
	}

	key := string(rolePath) + string(dataPath)
	hashedKey := sha256.Sum256([]byte(key))

	return fmt.Sprintf("%s%064x", cachePrefix, hashedKey), nil
}
