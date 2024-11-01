package acme

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
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
