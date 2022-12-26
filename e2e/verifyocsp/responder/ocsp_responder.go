// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package responder

import (
	"os"
	"os/exec"
	"path/filepath"
)

var DefaultOCSPResponderArgs = OCSPResponderArgs{
	IndexFile:    "./index.txt",
	ServerPort:   "9999",
	OCSPKeyPath:  filepath.Join("..", "test", "keys", "ecdsa-private.pem"), // see test/gen_certs.go
	OCSPCertPath: filepath.Join("..", "test", "certs", "root.pem"),         // see test/gen_certs.go
	CACertPath:   filepath.Join("..", "test", "certs", "root.pem"),
}

// OCSPResponderArgs specifies the arguments for the OCSP Responder.
type OCSPResponderArgs struct {
	// IndexFile is the Certificate status index file
	IndexFile string

	// ServerPort is the Port to run responder on.
	ServerPort string

	// OCSPKeyPath is the Responder key to sign responses with.
	OCSPKeyPath string

	// OCSPCertPath is the Responder certificate to sign responses with.
	OCSPCertPath string

	// CACertPath is CA certificate filename.
	CACertPath string
}

// StartOCSPResponder runs the OCSP responder.
func StartOCSPResponder(args OCSPResponderArgs) error {
	// ensure that the index file exists.
	// if not, create is using the ./add_cert_to_index.sh
	_, err := os.Stat(args.IndexFile)
	if err != nil {
		return err
	}

	cmd := exec.Command("openssl", []string{
		"ocsp", "-text",
		"-index", args.IndexFile,
		"-port", args.ServerPort,
		"-rsigner", args.OCSPCertPath,
		"-rkey", args.OCSPKeyPath,
		"-CA", args.CACertPath,
	}...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
