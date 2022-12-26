// Copyright (c) 2019-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package verifyocsp

import (
	"github.com/sylabs/singularity/e2e/internal/e2e"
	"github.com/sylabs/singularity/e2e/internal/testhelper"
	"github.com/sylabs/singularity/e2e/verifyocsp/responder"
	"path/filepath"
	"testing"
	"time"
)

type ctx struct {
	e2e.TestEnv
}

func (c *ctx) verifyocsp(t *testing.T) {
	keyPath := filepath.Join("..", "test", "keys", "ed25519-private.pem")
	certPath := filepath.Join("..", "test", "certs", "leaf.pem")
	intPath := filepath.Join("..", "test", "certs", "intermediate.pem")
	rootPath := filepath.Join("..", "test", "certs", "root.pem")

	// initiate OCSP responder to validate the singularity certificate chain
	go func() {
		args := responder.OCSPResponderArgs{
			IndexFile:    filepath.Join("./verifyocsp", "responder", "index.txt"),
			ServerPort:   "9999",
			OCSPKeyPath:  keyPath,
			OCSPCertPath: rootPath,
			CACertPath:   rootPath,
		}

		if err := responder.StartOCSPResponder(args); err != nil {
			t.Fatalf("responder failed due to %s", err)
		}
	}()

	time.Sleep(5 * time.Second)

	tests := []struct {
		name       string
		envs       []string
		flags      []string
		imagePath  string
		expectCode int
		expectOps  []e2e.SingularityCmdResultOp
	}{
		{
			name: "OCSPFlags",
			flags: []string{
				"--certificate", certPath,
				"--certificate-intermediates", intPath,
				"--certificate-roots", rootPath,
				"--ocsp-verify",
			},
			imagePath:  filepath.Join("..", "test", "images", "one-group-signed-dsse.sif"),
			expectCode: 255,
			expectOps: []e2e.SingularityCmdResultOp{
				// Expect OCSP to fail due to https://github.com/sylabs/singularity/issues/1152
				e2e.ExpectError(e2e.ContainMatch, "Failed to verify container: OCSP verification has failed"),
			},
		},
		{
			name: "OCSPEnvVars",
			envs: []string{
				"SINGULARITY_VERIFY_CERTIFICATE=" + certPath,
				"SINGULARITY_VERIFY_INTERMEDIATES=" + intPath,
				"SINGULARITY_VERIFY_ROOTS=" + rootPath,
				"SINGULARITY_VERIFY_OCSP=true",
			},
			imagePath:  filepath.Join("..", "test", "images", "one-group-signed-dsse.sif"),
			expectCode: 255,
			expectOps: []e2e.SingularityCmdResultOp{
				// Expect OCSP to fail due to https://github.com/sylabs/singularity/issues/1152
				e2e.ExpectError(e2e.ContainMatch, "Failed to verify container: OCSP verification has failed"),
			},
		},
		{
			name: "OCSPThirdPartyChain",
			flags: []string{
				"--certificate", filepath.Join("./verifyocsp", "thirdparty-certificates", "leaf.pem"),
				"--certificate-intermediates", filepath.Join("./verifyocsp", "thirdparty-certificates", "intermediate.pem"),
				"--ocsp-verify",
			},
			imagePath:  filepath.Join("..", "test", "images", "one-group-signed-dsse.sif"),
			expectCode: 255,
			expectOps: []e2e.SingularityCmdResultOp{
				// Expect OCSP to succeed, but signature verification to fail.
				e2e.ExpectError(e2e.ContainMatch, "Failed to verify container: integrity: signature object 3 not valid: dsse: verify envelope failed: Accepted signatures do not match threshold, Found: 0, Expected 1"),
			},
		},
	}

	for _, tt := range tests {
		c.RunSingularity(t,
			e2e.AsSubtest(tt.name),
			e2e.WithProfile(e2e.UserProfile),
			e2e.WithEnv(tt.envs),
			e2e.WithCommand("verify"),
			e2e.WithArgs(append(tt.flags, tt.imagePath)...),
			e2e.ExpectExit(tt.expectCode, tt.expectOps...),
		)
	}
}

// E2ETests is the main func to trigger the test suite
func E2ETests(env e2e.TestEnv) testhelper.Tests {
	c := ctx{
		TestEnv: env,
	}

	return testhelper.Tests{
		"ordered": func(t *testing.T) {
			t.Run("Verify OCSP", c.verifyocsp)
		},
	}
}
