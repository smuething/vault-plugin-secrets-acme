package acme

import (
	"crypto/sha256"
	"crypto/x509"
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
