package singularity_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sylabs/singularity/internal/app/singularity"
)

func TestOnlineRevocationCheck(t *testing.T) {
	var chain []*x509.Certificate

	// Get the server certificate
	serverPemFile := filepath.Join("..", "..", "..", "test", "ocsp", "e2e", "leaf.pem")
	serverPemBytes, err := os.ReadFile(serverPemFile)
	if err != nil {
		t.Fatalf("Failed to get server PEM. Err:%s", err)
	}

	serverPem, err := cryptoutils.UnmarshalCertificatesFromPEM(serverPemBytes)
	if err != nil {
		t.Fatalf("Failed to decode server PEM. Err:%s", err)
	}

	chain = append(chain, serverPem...)

	// Get the intermediate certificate
	intermediatePemFile := filepath.Join("..", "..", "..", "test", "ocsp", "e2e", "intermediate.pem")
	intermediatePemBytes, err := os.ReadFile(intermediatePemFile)
	if err != nil {
		t.Fatalf("Failed to get chain PEM. Err:%s", err)
	}

	intermediatePem, err := cryptoutils.UnmarshalCertificatesFromPEM(intermediatePemBytes)
	if err != nil {
		t.Fatalf("Failed to decode intermediate PEM. Err:%s", err)
	}

	chain = append(chain, intermediatePem...)

	// note: occasionally the validation may fail due to inability to access akamai OCSP.
	// normally after 2-3 tries it should succeed.
	if err := singularity.OnlineRevocationCheck(chain...); err != nil {
		t.Fatalf("OCSP verification has failed. Err:%s", err)
	}
}
