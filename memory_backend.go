package main

import (
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
	getAuths() map[string]authorization
	getSignerID(userid, keyid string) (int, error)
	makeSignerIndex([]signer.Signer) error
}

// inMemoryBackend is an authBackend that loads a config and stores
// that auth info in memory
type inMemoryBackend struct {
	auths       map[string]authorization
	signerIndex map[string]int
}

// newInMemoryAuthBackend returns an empty inMemoryBackend
func newInMemoryAuthBackend() (backend *inMemoryBackend) {
	return &inMemoryBackend{
		auths:       make(map[string]authorization),
		signerIndex: make(map[string]int),
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
	return nil
}

// getAuthByID returns an authorization if it exists or nil. Call
// addAuthorizations and addMonitoring first
func (b *inMemoryBackend) getAuthByID(id string) (authorization, error) {
	if auth, ok := b.auths[id]; ok {
		return auth, nil
	}
	return authorization{}, ErrAuthNotFound
}

// getAuths returns enabled authorizations
func (b *inMemoryBackend) getAuths() map[string]authorization {
	return b.auths
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
	tag := userid + "+" + keyid
	if _, ok := b.signerIndex[tag]; !ok {
		if keyid == "" {
			return -1, errors.Errorf("%q does not have a default signing key", userid)
		}
		return -1, errors.Errorf("%s is not authorized to sign with key ID %s", userid, keyid)
	}
	return b.signerIndex[tag], nil
}

// makeSignerIndex creates a map of authorization IDs and signer IDs to
// quickly locate a signer based on the user requesting the signature.
func (b *inMemoryBackend) makeSignerIndex(signers []signer.Signer) error {
	// add an entry for each authid+signerid pair
	for id, auth := range b.getAuths() {
		if id == monitorAuthID {
			// the "monitor" authorization is a special case
			// that doesn't need a signer index
			continue
		}
		// if the authorization has no signer configured, error out
		if len(auth.Signers) < 1 {
			return errors.Errorf("auth id %q must have at least one signer configured", id)
		}
		for _, sid := range auth.Signers {
			// make sure the sid is valid
			sidExists := false

			for pos, s := range signers {
				if sid == s.Config().ID {
					sidExists = true
					log.Printf("Mapping auth id %q and signer id %q to signer %d with hawk ts validity %s", auth.ID, s.Config().ID, pos, auth.hawkMaxTimestampSkew)
					tag := auth.ID + "+" + s.Config().ID
					b.signerIndex[tag] = pos
				}
			}

			if !sidExists {
				return errors.Errorf("in auth id %q, signer id %q was not found in the list of known signers", auth.ID, sid)
			}
		}
		// add a default entry for the signer, such that if none is provided in
		// the signing request, the default is used
		for pos, signer := range signers {
			if auth.Signers[0] == signer.Config().ID {
				log.Printf("Mapping auth id %q to default signer %d with hawk ts validity %s", auth.ID, pos, auth.hawkMaxTimestampSkew)
				tag := auth.ID + "+"
				b.signerIndex[tag] = pos
				break
			}
		}
	}
	return nil
}
