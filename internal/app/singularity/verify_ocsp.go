// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// Copyright (c) 2020-202, ICS-FORTH.  All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package singularity

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/sylabs/singularity/pkg/sylog"
	"golang.org/x/crypto/ocsp"
)

/*
Online Certificate Status Protocol - OCSP

OCSP responder is used to provide real-time verification of the revocation status of an X.509 certificate.
RFC: https://www.rfc-editor.org/rfc/rfc6960
*/

const (
	PKIXOCSPNoCheck = "1.3.6.1.5.5.7.48.1.5"
)

var (
	errOCSP = errors.New("OCSP verification has failed")
)

func OCSPVerify(chain ...*x509.Certificate) error {
	// use the pool as an index for certificate issuers.
	// fixme: we can drop this lookup if we assume that certificate N is always signed by certificate N+1.
	pool := map[string]*x509.Certificate{}

	for _, cert := range chain {
		pool[string(cert.SubjectKeyId)] = cert
	}

	// recursively validate the certificate chain
	for _, cert := range chain {
		if err := validateCertificate(cert, pool); err != nil {
			sylog.Warningf("OCSP verification has failed. Err: %s", err)
			return errOCSP
		}
	}

	return nil
}

func validateCertificate(cert *x509.Certificate, pool map[string]*x509.Certificate) error {
	if len(cert.AuthorityKeyId) == 0 || string(cert.SubjectKeyId) == string(cert.AuthorityKeyId) {
		sylog.Infof("skip self-signed certificate (%s)", cert.Subject.String())

		return nil
	}

	/*---------------------------------------------------
	 * Retrieve the CA who issued the certificate in question.
	 *---------------------------------------------------*/

	// firstly, look for the issuer in the pool of certificates.
	issuer, exists := pool[string(cert.AuthorityKeyId)]
	if !exists {
		// if not found anywhere locally, try to download it
		missingCerts, err := downloadCertsFromURLs(cert.IssuingCertificateURL...)
		if err != nil {
			return errors.Wrapf(err, "download cert error")
		}

		// if that does not work either, just abort
		issuer, exists = missingCerts[string(cert.AuthorityKeyId)]
		if !exists {
			return errors.Errorf("cannot find issuer '%s'", cert.Issuer)
		}
	}

	sylog.Infof("Validate: cert:%s  issuer:%s", cert.Subject.CommonName, issuer.Subject.CommonName)

	/*---------------------------------------------------
	 * Ask OCSP for the validity of signer's certificate.
	 * Also make sure that the OCSP is trustworthy.
	 *---------------------------------------------------*/
	ocspCertificate, err := queryOCSP(cert, issuer)
	if err != nil {
		return errors.Wrapf(err, "OCSP Query")
	}

	if ocspCertificate != nil {
		// The CA requires us to explicitly trust this certificate
		// RFC-6960 Section: 4.2.2.2.1
		for _, extension := range cert.Extensions {
			if extension.Id.String() == PKIXOCSPNoCheck {
				goto skipOCSPVerification
			}
		}

		// avoid loops cause by misconfigured OCSP responders
		if string(cert.SubjectKeyId) == string(ocspCertificate.SubjectKeyId) {
			return nil
		}

		// make sure that the OCSP server is trustworthy
		if err := validateCertificate(ocspCertificate, pool); err != nil {
			return errors.Wrapf(err, "cannot verify OCSP server's certificate")
		}

	skipOCSPVerification:
	}

	return nil
}

func queryOCSP(cert, issuer *x509.Certificate) (needsValidation *x509.Certificate, err error) {

	logrus.Warnf("cert:[%s] issuer:[%s]", cert.Subject.String(), issuer.Subject.String())

	if !issuer.IsCA {
		return nil, errors.Errorf("signer's certificates can only belong to a CA")
	}

	/*---------------------------------------------------
	 * Extract OCSP Server from the certificate in question
	 *---------------------------------------------------*/
	if len(cert.OCSPServer) == 0 {
		return nil, errors.Wrapf(err, "certificate does not support OCSP")
	}

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	ocspURL, err := url.Parse(cert.OCSPServer[0])
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse OCSP Server from certificate")
	}

	/*---------------------------------------------------
	 * Create OCSP Request
	 *---------------------------------------------------*/
	// Hash contains the hash function that should be used when
	// constructing the OCSP request. If zero, SHA-1 will be used.
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}

	buffer, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "OCSP Create Request")
	}

	httpRequest, err := http.NewRequest(http.MethodPost, cert.OCSPServer[0], bytes.NewBuffer(buffer))
	if err != nil {
		return nil, errors.Wrapf(err, "HTTP Create Request")
	}

	// Submit OCSP Request
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, errors.Wrapf(err, "OCSP Send Request")
	}

	defer httpResponse.Body.Close()

	/*---------------------------------------------------
	 * Parse OCSP Response
	 *---------------------------------------------------*/
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read response body")
	}

	ocspResponse, err := ocsp.ParseResponseForCert(output, cert, issuer)
	if err != nil {
		return nil, errors.Wrapf(err, "OCSP response error")
	}

	/*---------------------------------------------------
	 * Handle OCSP Response
	 *---------------------------------------------------*/
	// The OCSP's certificate is signed by a third-party issuer that we need to verify.
	if ocspResponse.Certificate != nil {
		needsValidation = ocspResponse.Certificate
	}

	// Check validity
	switch ocspResponse.Status {
	case ocsp.Good: // means the certificate is still valid
		return needsValidation, nil

	case ocsp.Revoked: // says the certificate was revoked and cannot be trusted
		return needsValidation, errors.Errorf("certificate revoked at '%s'. Revocation reason code: '%d'",
			ocspResponse.RevokedAt, ocspResponse.RevocationReason)

	default: // states that the server does not know about the requested certificate,
		return needsValidation, errors.Errorf("status unknown. certificate cannot be trusted")
	}
}

func downloadCertsFromURLs(urls ...string) (map[string]*x509.Certificate, error) {
	certs := map[string]*x509.Certificate{}

	for _, certURL := range urls {
		sylog.Infof("Downloading certificate from ", certURL)

		//nolint:gosec
		// Alternative:  GOSEC=gosec -quiet -exclude=G104,G107
		resp, err := http.Get(certURL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get certificate from '%s'", certURL)
		}

		caCertBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read CA certificate's body frin '%s'", certURL)
		}

		if err := resp.Body.Close(); err != nil {
			return nil, errors.Wrapf(err, "resp closing error: '%s'", err)
		}

		// decode raw data as DER
		cert, err := x509.ParseCertificate(caCertBody)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode certificate from '%s'", certURL)
		}

		// add certs to the chain
		certs[string(cert.SubjectKeyId)] = cert
	}

	return certs, nil
}
