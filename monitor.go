package main

import (
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer"
	"net/http"
	"sync"
	"time"
)

// A monitor of signer health
type monitor struct {
	// Read-only.
	signers []signer.Signer

	// Results from checking signers.
	sigerrstrs []string
	sigresps   []formats.SignatureResponse

	// Protects sigerrstrs and sigresps.
	sync.RWMutex

	// Used to signal, by closing it, that the results
	// have been populated with an initial check
	initialized chan interface{}

	// Proxy to autographer.authorize.
	authorize func(r *http.Request, body []byte) (userid string, err error)

	// Copy of autographer.debug.
	debug bool

	// Closed on exit of the autographer instance.
	exit chan interface{}
}

// The monitor loop, should run in a separate goroutine.
func (m *monitor) start(interval string) {
	duration, err := time.ParseDuration(interval)
	if err != nil {
		log.Fatal(err)
	}
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	// Perform an initial check.
	m.checkSigners()
	close(m.initialized)

	for {
		select {
		case <-ticker.C:
			m.checkSigners()
		case <-m.exit:
			return
		}
	}
}

func (m *monitor) checkSigners() {
	m.Lock()
	defer m.Unlock()

	for i, s := range m.signers {
		// First try the DataSigner interface. If the signer doesn't
		// implement it, try the FileSigner interface. If that's still
		// not implemented, return an error.
		if _, ok := s.(signer.DataSigner); ok {
			// sign with data set to the base64 of the string 'AUTOGRAPH MONITORING'
			sig, err := s.(signer.DataSigner).SignData(MonitoringInputData, s.(signer.DataSigner).GetDefaultOptions())
			if err != nil {
				m.sigerrstrs[i] = fmt.Sprintf("signing failed with error: %v", err)
				continue
			}

			encodedsig, err := sig.Marshal()
			if err != nil {
				m.sigerrstrs[i] = fmt.Sprintf("encoding failed with error: %v", err)
				continue
			}
			m.sigerrstrs[i] = ""
			m.sigresps[i] = formats.SignatureResponse{
				Ref:        id(),
				Type:       s.Config().Type,
				Mode:       s.Config().Mode,
				SignerID:   s.Config().ID,
				PublicKey:  s.Config().PublicKey,
				Signature:  encodedsig,
				X5U:        s.Config().X5U,
				SignerOpts: s.Config().SignerOpts,
			}
			continue
		}

		if _, ok := s.(signer.FileSigner); ok {
			// Signers that only implement the FileSigner interface must
			// also implement the TestFileGetter interface to return a valid
			// test file that can be used here to monitor the signer.
			if _, ok := s.(signer.TestFileGetter); !ok {
				m.sigerrstrs[i] = fmt.Sprintf("signer %q implements FileSigner but not the TestFileGetter interface", s.Config().ID)
				continue
			}
			output, err := s.(signer.FileSigner).SignFile(s.(signer.TestFileGetter).GetTestFile(), s.(signer.FileSigner).GetDefaultOptions())
			if err != nil {
				m.sigerrstrs[i] = fmt.Sprintf("signing failed with error: %v", err)
				continue
			}
			signedfile := base64.StdEncoding.EncodeToString(output)
			m.sigerrstrs[i] = ""
			m.sigresps[i] = formats.SignatureResponse{
				Ref:        id(),
				Type:       s.Config().Type,
				Mode:       s.Config().Mode,
				SignerID:   s.Config().ID,
				PublicKey:  s.Config().PublicKey,
				SignedFile: signedfile,
				X5U:        s.Config().X5U,
				SignerOpts: s.Config().SignerOpts,
			}
			continue
		}

		m.sigerrstrs[i] = fmt.Sprintf("signer %q does not implement DataSigner or FileSigner interfaces", s.Config().ID)
	}
}

func newMonitor(ag *autographer, interval string) *monitor {
	m := new(monitor)
	m.authorize = func(r *http.Request, body []byte) (userid string, err error) {
		return ag.authorize(r, body)
	}
	signers := ag.getSigners()
	m.signers = signers
	m.sigerrstrs = make([]string, len(signers))
	m.sigresps = make([]formats.SignatureResponse, len(signers))
	m.initialized = make(chan interface{})
	m.exit = ag.exit
	m.debug = ag.debug

	go m.start(interval)

	return m
}
