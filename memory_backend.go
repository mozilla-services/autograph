package main

import (
	"time"

	"github.com/pkg/errors"
)

// authBackend is an interface for finding HAWK users and their
// permissions
type authBackend interface {
	addAuth(*authorization) error
	getAuthByID(id string) (authorization, error)
	getAuths() map[string]authorization
}

// inMemoryBackend is an authBackend that loads a config and stores
// that auth info in memory
type inMemoryBackend struct {
	auths map[string]authorization
}

// newInMemoryAuthBackend returns an empty inMemoryBackend
func newInMemoryAuthBackend() (backend *inMemoryBackend) {
	return &inMemoryBackend{
		auths: make(map[string]authorization),
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
