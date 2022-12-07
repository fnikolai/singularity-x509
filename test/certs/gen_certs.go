// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sirupsen/logrus"
)

var start = time.Date(2020, 4, 1, 0, 0, 0, 0, time.UTC)

// createCertificate creates a new X.509 certificate.
func createCertificate(tmpl, parent *x509.Certificate, pub, pri any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, pri)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// createRoot creates a self-signed root certificate using the supplied key.
func createRoot(start time.Time, key crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Sylabs Inc."},
			CommonName:   "root",
		},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		OCSPServer:            []string{"http://localhost:9999"},
	}

	return createCertificate(tmpl, tmpl, key.(crypto.Signer).Public(), key)
}

// createIntermediate creates an intermediate certificate using the supplied parent and keys.
func createIntermediate(start time.Time, key crypto.PublicKey, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Sylabs Inc."},
			CommonName:   "intermediate",
		},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		OCSPServer:            []string{"http://localhost:9999"},
	}

	return createCertificate(tmpl, parent, key, parentKey)
}

// createIntermediate creates a leaf certificate using the supplied parent and keys.
func createLeaf(start time.Time, key crypto.PublicKey, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Sylabs Inc."},
			CommonName:   "leaf",
		},
		NotBefore: start,
		NotAfter:  start.AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
		MaxPathLenZero: true,
		OCSPServer:     []string{"http://localhost:9999"},
	}

	return createCertificate(tmpl, parent, key, parentKey)
}

func loadKeys(keyPrefix string) (crypto.PrivateKey, crypto.PublicKey, error) {
	// Create a new key for the CA
	pem, err := os.ReadFile(filepath.Join("..", "keys", keyPrefix+"private.pem"))
	if err != nil {
		return nil, nil, err
	}

	pri, err := cryptoutils.UnmarshalPEMToPrivateKey(pem, cryptoutils.SkipPassword)
	if err != nil {
		return nil, nil, err
	}

	pub := pri.(crypto.Signer).Public()

	return pri, pub, nil
}

// writeCerts generates certificates and writes them to disk.
func writeCerts() error {
	// create a new key for the CA
	rootPri, _, err := loadKeys("")
	if err != nil {
		return errors.Wrap(err, "failed to load root keys")
	}

	// create a new key for the OCSP
	_, intermediatePub, err := loadKeys("intermediate_")
	if err != nil {
		return errors.Wrap(err, "failed to load intermediate keys")
	}

	// create a new key for the Client
	_, leafPub, err := loadKeys("leaf_")
	if err != nil {
		return errors.Wrap(err, "failed to load leaf keys")
	}

	// Create a CA certificate and self-sign it using the CA key.
	logrus.Infof("Creating Root certificate")
	root, err := createRoot(start, rootPri)
	if err != nil {
		return err
	}

	// Sign the OCSP Certificate with the CA key.
	logrus.Infof("Creating Intermediate certificate")
	intermediate, err := createIntermediate(start, intermediatePub, root, rootPri)
	if err != nil {
		return err
	}

	// Sign the Client Certificate with the OCSP key
	logrus.Infof("Creating Leaf certificate")
	leaf, err := createLeaf(start, leafPub, root, rootPri)
	if err != nil {
		return err
	}

	outputs := []struct {
		cert *x509.Certificate
		path string
	}{
		{
			cert: root,
			path: "root.pem",
		},
		{
			cert: intermediate,
			path: "intermediate.pem",
		},
		{
			cert: leaf,
			path: "leaf.pem",
		},
	}

	for _, output := range outputs {
		b, err := cryptoutils.MarshalCertificateToPEM(output.cert)
		if err != nil {
			return err
		}

		if err := os.WriteFile(output.path, b, 0o644); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if err := writeCerts(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
