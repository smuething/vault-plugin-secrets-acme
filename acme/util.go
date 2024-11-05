package acme

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
)

func GetSHA256Thumbprint(cert *x509.Certificate) string {

	thumbprint := sha256.Sum256(cert.Raw)

	var buf strings.Builder
	for i, b := range thumbprint {
		if i > 0 {
			buf.WriteString(":")
		}
		fmt.Fprintf(&buf, "%02X", b)
	}
	return buf.String()
}

func GetCertID(cert *x509.Certificate) string {
	ariCertID, err := certificate.MakeARICertID(cert)
	if err != nil {
		// there is probably no ARI extension on the certificate, fall back to thumbprint
		return GetSHA256Thumbprint(cert)
	}
	return ariCertID
}

func ConvertToMapStringAny(source any) map[string]any {
	marshaled, err := json.Marshal(source)
	if err != nil {
		panic(err)
	}
	result := make(map[string]any)
	if err = json.Unmarshal(marshaled, &result); err != nil {
		panic(err)
	}
	return result
}

type PrivateKey struct {
	crypto.PrivateKey
}

func (key *PrivateKey) MarshalText() ([]byte, error) {
	if key == nil {
		return []byte(""), nil
	}
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

func (key *PrivateKey) UnmarshalText(text []byte) error {
	block, _ := pem.Decode(text)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key.PrivateKey = privateKey
	return err
}
