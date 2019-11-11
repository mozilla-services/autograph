package formats

import (
	"fmt"
	"regexp"
	"time"
)

// AuthIDFormat is a regex for the format IDs must follow
//
// * at least three alphanumeric, dash, or underscore chars
// * cannot start with a dash or underscore
//
const AuthIDFormat = `^[a-zA-Z0-9][a-zA-Z0-9-_]{2,64}$`

// authIDRe is the compiled regular expression for matching AuthIDs
var authIDRe = regexp.MustCompile(AuthIDFormat)

// Authorization is HAWK credentials and permitted signer IDs to use
type Authorization struct {
	ID                    string
	Key                   string
	Signers               []string
	HawkTimestampValidity time.Duration
}

// Validate checks the Authorization ID format, Authorization key
// length, and signer ID formats
func (a *Authorization) Validate() (err error) {
	if !authIDRe.MatchString(a.ID) {
		return fmt.Errorf("Invalid auth ID %q does not match format %q", a.ID, AuthIDFormat)
	}
	if len(a.Key) < 32 {
		return fmt.Errorf("Invalid auth Key is too short (must be at least 64 chars")
	}
	for _, signerID := range a.Signers {
		err = ValidateSignerID(signerID)
		if err != nil {
			return fmt.Errorf("Invalid auth signer ID %q: %q", signerID, err)
		}
	}
	return
}
