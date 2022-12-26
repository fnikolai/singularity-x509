package standalone

import (
	"fmt"
	"github.com/sylabs/singularity/e2e/verifyocsp/responder"
	"os"
)

func main() {
	if err := responder.StartOCSPResponder(responder.DefaultOCSPResponderArgs); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
