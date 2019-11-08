package formats

import (
	"time"
)

// Authorization is HAWK credentials and permitted signer IDs to use
type Authorization struct {
	ID                    string
	Key                   string
	Signers               []string
	HawkTimestampValidity time.Duration
}
