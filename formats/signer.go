package formats

import (
	"fmt"
	"regexp"
)

// SignerIDFormat is a regex for the format IDs must follow
const SignerIDFormat = `^[a-zA-Z0-9-_]{1,64}$`

// authIDRe is the compiled regular expression for matching AuthIDs
var signerIDRe = regexp.MustCompile(SignerIDFormat)

// ValidateSignerID checks that a SignerID matches ^[a-zA-Z0-9-_]{1,64}$
func ValidateSignerID(signerID string) error {
	if !signerIDRe.MatchString(signerID) {
		return fmt.Errorf("signer ID %q does not match the permitted format %q",
			signerID, SignerIDFormat)
	}
	return nil
}
