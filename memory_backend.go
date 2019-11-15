package main

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"go.mozilla.org/autograph/signer"
)

// authBackend is an interface for adding and finding HAWK users and
// their permissions
type authBackend interface {
	addAuth(*authorization) error
	addMonitoringAuth(string) error
	getAuthByID(id string) (authorization, error)
	addSigner(signer.Signer)
	getSigners() []signer.Signer
	getSignerForUser(userID, signerID string) (signer.Signer, error)
}

// inMemoryBackend is an authBackend that loads a config and stores
// that auth info in memory
type inMemoryBackend struct {
	auths       map[string]authorization
	signerIndex map[string]int
	signers     []signer.Signer
}

// newInMemoryAuthBackend returns an empty inMemoryBackend
func newInMemoryAuthBackend() (backend *inMemoryBackend) {
	return &inMemoryBackend{
		auths:       make(map[string]authorization),
		signerIndex: make(map[string]int),
		signers:     []signer.Signer{},
	}
}

// addAuth adds an authorization to the auth map or errors
func (b *inMemoryBackend) addAuth(auth *authorization) (err error) {
	_, getAuthErr := b.getAuthByID(auth.ID)
	switch getAuthErr {
	case nil:
		return errors.Errorf("authorization id '%s' already defined, duplicates are not permitted", auth.ID)
	case ErrAuthNotFound:
		// this is what we want
	default:
		return errors.Wrapf(getAuthErr, "error finding auth with id '%s'", auth.ID)
	}
	if auth.HawkTimestampValidity != "" {
		auth.hawkMaxTimestampSkew, err = time.ParseDuration(auth.HawkTimestampValidity)
		if err != nil {
			return err
		}
	} else {
		auth.hawkMaxTimestampSkew = time.Minute
	}
	b.auths[auth.ID] = *auth
	return b.addAuthToSignerIndex(auth)
}

// getAuthByID returns an authorization if it exists or nil. Call
// addAuthorizations and addMonitoring first
func (b *inMemoryBackend) getAuthByID(id string) (authorization, error) {
	if auth, ok := b.auths[id]; ok {
		return auth, nil
	}
	return authorization{}, ErrAuthNotFound
}

// addMonitoringAuth adds an authorization to enable the
// tools/autograph-monitor
func (b *inMemoryBackend) addMonitoringAuth(monitorKey string) error {
	_, err := b.getAuthByID(monitorAuthID)
	switch err {
	case ErrAuthNotFound:
	case nil:
		return errors.Errorf("user 'monitor' is reserved for monitoring, duplication is not permitted")
	default:
		return errors.Errorf("error fetching 'monitor' auth: %q", err)
	}
	return b.addAuth(&authorization{
		ID:                    monitorAuthID,
		Key:                   monitorKey,
		HawkTimestampValidity: "1m",
		hawkMaxTimestampSkew:  time.Minute,
	})
}

// getSignerId returns the signer identifier for the user. If a keyid
// is specified, the corresponding signer is returned. If no signer is
// found, an error is returned and the signer identifier is set to -1.
func (b *inMemoryBackend) getSignerID(userid, keyid string) (int, error) {
	tag := getSignerIndexTag(userid, keyid)
	if _, ok := b.signerIndex[tag]; !ok {
		if keyid == "" {
			return -1, errors.Errorf("%q does not have a default signing key", userid)
		}
		return -1, errors.Errorf("%s is not authorized to sign with key ID %s", userid, keyid)
	}
	return b.signerIndex[tag], nil
}

// addSigner adds a newly configured signer
func (b *inMemoryBackend) addSigner(signer signer.Signer) {
	b.signers = append(b.signers, signer)
}

// getSigners returns all configured signers
func (b *inMemoryBackend) getSigners() []signer.Signer {
	return b.signers
}

// getSignerForUser returns the signer with the given ID for the
// provided hawk ID or an error
func (b *inMemoryBackend) getSignerForUser(userID, signerID string) (signer.Signer, error) {
	signerIndexID, err := b.getSignerID(userID, signerID)
	if err != nil || signerIndexID < 0 {
		return nil, err
	}
	return b.getSigners()[signerIndexID], nil
}

// getSignerIndexTag returns the tag to lookup the signer for a hawk user
func getSignerIndexTag(authID, signerID string) string {
	return fmt.Sprintf("%s+%s", authID, signerID)
}

// addAuthToSignerIndex
func (b *inMemoryBackend) addAuthToSignerIndex(auth *authorization) error {
	// the "monitor" authorization is doesn't need a signer index
	if auth.ID == monitorAuthID {
		return nil
	}
	// authorization must have a signer configured
	if len(auth.Signers) < 1 {
		return errors.Errorf("auth id %q must have at least one signer configured", auth.ID)
	}
	// add an authid+signerid entry for each signer the auth grants access to
	for _, sid := range auth.Signers {
		// make sure the sid is valid
		sidExists := false

		for pos, s := range b.signers {
			if sid == s.Config().ID {
				sidExists = true
				log.Printf("Mapping auth id %q and signer id %q to signer %d with hawk ts validity %s", auth.ID, s.Config().ID, pos, auth.hawkMaxTimestampSkew)
				b.signerIndex[getSignerIndexTag(auth.ID, s.Config().ID)] = pos
			}
		}

		if !sidExists {
			return errors.Errorf("in auth id %q, signer id %q was not found in the list of known signers", auth.ID, sid)
		}
	}
	// add a default entry for the signer, such that if none is provided in
	// the signing request, the default is used
	for pos, signer := range b.signers {
		if auth.Signers[0] == signer.Config().ID {
			log.Printf("Mapping auth id %q to default signer %d with hawk ts validity %s", auth.ID, pos, auth.hawkMaxTimestampSkew)
			tag := auth.ID + "+"
			b.signerIndex[tag] = pos
			break
		}
	}
	return nil
}
