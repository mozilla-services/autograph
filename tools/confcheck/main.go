package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/mozilla-services/autograph/signer"
	"github.com/mozilla-services/yaml"
)

// configuration is the YAML config. It's a reproduction of what's in main.go,
// and we should consider consolidating these. However, the real problem is the
// singer.Configurations that are modifiable in place. Not great!
type configuration struct {
	Signers        []signer.Configuration
	Authorizations []authorization
}

// FIXME move this type into signer.Configuration, too
type signerID string
type authorization struct {
	ID      string
	Key     string
	Signers []signerID
}

// No duplicates in the authorizations
func main() {
	config := &configuration{}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("unable to read from stdin: %s", err)
	}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		log.Fatalf("error unmarshalling config: %s", err)
	}
	errors, fatalErr := verify(config)
	if fatalErr != nil {
		log.Fatalf("fatal error verifying config and cannot continue processing: %s", fatalErr)
	}
	if len(errors) > 0 {
		for _, e := range errors {
			fmt.Fprintln(os.Stderr, e.msg)
		}
		os.Stderr.Sync()
		os.Exit(5)
	}
	return
}

type configError struct {
	msg string
}

func newConfigError(template string, args ...interface{}) configError {
	return configError{fmt.Sprintf(template, args...)}
}

func verify(config *configuration) ([]configError, error) {
	var errors []configError
	for i, auth := range config.Authorizations {
		for j, other := range config.Authorizations {
			if i == j {
				continue
			}
			if auth.ID == other.ID {
				errors = append(errors, newConfigError("duplicate authorization ID: %s", auth.ID))
			}
		}
	}
	signerIDs := configuredSignerIDs(config)
	origToNewSignerID := migratingSignerIds(signerIDs)

	for _, auth := range config.Authorizations {
		errs := dupeSigners(auth)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
		errs = checkMissingSigners(auth, signerIDs)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
		// FIXME only run this in prod and only for a lil while
		errs = checkShouldHaveMigratingSigners(auth, origToNewSignerID)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
	}
	return errors, nil
}

func dupeSigners(auth authorization) []configError {
	var errors []configError
	for i, signer := range auth.Signers {
		for j, other := range auth.Signers {
			if i == j {
				continue
			}
			if signer == other {
				errors = append(errors, newConfigError("authorization %#v has duplicate signer ID: %#v", auth.ID, signer))
			}
		}
	}
	return errors
}

func configuredSignerIDs(config *configuration) map[signerID]bool {
	signerIDs := make(map[signerID]bool)
	for _, signer := range config.Signers {
		signerIDs[signerID(signer.ID)] = true
	}
	return signerIDs
}

func checkMissingSigners(auth authorization, signerIDs map[signerID]bool) []configError {
	var errors []configError
	for _, signer := range auth.Signers {
		if !signerIDs[signer] {
			errors = append(errors, newConfigError("authorization %#v references unknown signer %#v", auth.ID, signer))
		}
	}
	return errors
}

func migratingSignerIds(signerIDs map[signerID]bool) map[signerID]signerID {
	oldIDToNewID := make(map[signerID]signerID)
	// Quick heuristic instead of a full list. Please don't rely on this in the future
	dateSuffixes := []string{"_202402", "_202404"}
	for _, dateSuffix := range dateSuffixes {
		for signer, _ := range signerIDs {
			// Has the suffix
			if strings.HasSuffix(string(signer), dateSuffix) && !strings.HasSuffix(string(signer), "_dep"+dateSuffix) {
				origId := signer[:len(signer)-len(dateSuffix)]
				if _, ok := signerIDs[origId]; ok {
					oldIDToNewID[origId] = signer
				}
			}
		}
	}
	return oldIDToNewID
}
func checkShouldHaveMigratingSigners(auth authorization, origToNewSignerID map[signerID]signerID) []configError {
	var errors []configError
	authSigners := make(map[signerID]bool)
	for _, signer := range auth.Signers {
		authSigners[signerID(signer)] = true
	}
	for _, signer := range auth.Signers {
		if newID, ok := origToNewSignerID[signer]; ok {
			if _, ok := authSigners[newID]; !ok {
				errors = append(errors, newConfigError("authorization %#v has signer %#v, but doesn't have signer: %#v", auth.ID, signer, newID))
			}
		}
	}
	return errors
}
