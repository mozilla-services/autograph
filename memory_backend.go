package main

// authBackend is an interface for finding HAWK users and their
// permissions
type authBackend interface {
}

// inMemoryBackend is an authBackend that loads a config and stores
// that auth info in memory
type inMemoryBackend struct {
}

// newInMemoryAuthBackend returns an empty inMemoryBackend
func newInMemoryAuthBackend() (backend *inMemoryBackend) {
	return &inMemoryBackend{}
}
