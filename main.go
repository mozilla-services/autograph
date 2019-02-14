// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

//go:generate ./version.sh

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	lru "github.com/hashicorp/golang-lru"

	"github.com/mozilla-services/yaml"

	"go.mozilla.org/autograph/database"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/contentsignature"

	"go.mozilla.org/autograph/signer/contentsignaturepki"
	"go.mozilla.org/autograph/signer/gpg2"
	"go.mozilla.org/autograph/signer/mar"
	"go.mozilla.org/autograph/signer/pgp"
	"go.mozilla.org/autograph/signer/rsapss"
	"go.mozilla.org/autograph/signer/xpi"

	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/ThalesIgnite/crypto11"
)

// configuration loads a yaml file that contains the configuration of Autograph
type configuration struct {
	Server struct {
		Listen         string
		NonceCacheSize int
		IdleTimeout    time.Duration
		ReadTimeout    time.Duration
		WriteTimeout   time.Duration
	}
	Statsd struct {
		Addr      string
		Namespace string
		Buflen    int
	}
	HSM            crypto11.PKCS11Config
	Database       database.Config
	Signers        []signer.Configuration
	Authorizations []authorization
	Monitoring     authorization
}

// An autographer is a running instance of an autograph service,
// with all signers and permissions configured
type autographer struct {
	db          *database.Handler
	stats       *statsd.Client
	signers     []signer.Signer
	auths       map[string]authorization
	signerIndex map[string]int
	nonces      *lru.Cache
	debug       bool
}

func main() {
	args := os.Args
	// e.g. when run as 'autograph -c config.yaml' strip leading autograph
	if len(args) > 0 {
		args = os.Args[1:]
	}
	run(parseArgsAndLoadConfig(args))
}

func parseArgsAndLoadConfig(args []string) (conf configuration, listen string, authPrint, debug bool) {
	var (
		cfgFile string
		port    string
		err     error
		fset    = flag.NewFlagSet("parseArgsAndLoadConfig", flag.ContinueOnError)
	)

	fset.StringVar(&cfgFile, "c", "autograph.yaml", "Path to configuration file")
	fset.StringVar(&port, "p", "", "Port to listen on. Overrides the listen var from the config file")
	fset.BoolVar(&authPrint, "A", false, "Print authorizations matrix and exit")
	fset.BoolVar(&debug, "D", false, "Print debug logs")
	fset.Parse(args)

	err = conf.loadFromFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	confListen := strings.Split(conf.Server.Listen, ":")
	if len(confListen) > 1 && port != "" && port != confListen[1] {
		listen = fmt.Sprintf("%s:%s", confListen[0], port)
		log.Infof("Overriding listen addr from config %s with new port from the commandline: %s", conf.Server.Listen, listen)
	} else {
		listen = conf.Server.Listen
	}

	return
}

func run(conf configuration, listen string, authPrint, debug bool) {
	var (
		ag  *autographer
		err error
	)

	// initialize signers from the configuration
	// and store them into the autographer handler
	ag = newAutographer(conf.Server.NonceCacheSize)

	// connect to the database
	if conf.Database.Name != "" {
		ag.db, err = database.Connect(conf.Database)
		if err != nil {
			log.Fatal(err)
		}
		if ag.db == nil {
			log.Fatal("failed to initialize database connection, unknown error")
		}
		// start a monitoring function that panics if
		// the db becomes inaccessible
		go ag.db.Monitor()
		log.Printf("database connection to %s/%s established", conf.Database.Host, conf.Database.Name)
	}

	// initialize the hsm if a configuration is defined
	if conf.HSM.Path != "" {
		tmpCtx, err := crypto11.Configure(&conf.HSM)
		if err != nil {
			log.Fatal(err)
		}
		if tmpCtx != nil {
			// if we successfully initialized the crypto11 context,
			// tell the signers they can try using the HSM
			for i := range conf.Signers {
				conf.Signers[i].HsmIsAvailable(tmpCtx)
			}
		}
	}

	if conf.Statsd.Addr != "" {
		err = ag.addStats(conf)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = ag.addSigners(conf.Signers)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addAuthorizations(conf.Authorizations)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addMonitoring(conf.Monitoring)
	if err != nil {
		log.Fatal(err)
	}
	ag.makeSignerIndex()
	if debug {
		ag.enableDebug()
	}

	if authPrint {
		ag.PrintAuthorizations()
		os.Exit(0)
	}

	ag.startCleanupHandler()

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/__heartbeat__", handleHeartbeat).Methods("GET")
	router.HandleFunc("/__lbheartbeat__", handleHeartbeat).Methods("GET")
	router.HandleFunc("/__version__", handleVersion).Methods("GET")
	router.HandleFunc("/__monitor__", ag.handleMonitor).Methods("GET")
	router.HandleFunc("/sign/file", ag.handleSignature).Methods("POST")
	router.HandleFunc("/sign/data", ag.handleSignature).Methods("POST")
	router.HandleFunc("/sign/hash", ag.handleSignature).Methods("POST")

	server := &http.Server{
		IdleTimeout:  conf.Server.IdleTimeout,
		ReadTimeout:  conf.Server.ReadTimeout,
		WriteTimeout: conf.Server.WriteTimeout,
		Addr:         listen,
		Handler: handleMiddlewares(
			router,
			setRequestID(),
			setRequestStartTime(),
			setResponseHeaders(),
			logRequest(),
		),
	}
	log.Infof("starting autograph on %s with timeouts: idle %s read %s write %s", listen, conf.Server.IdleTimeout, conf.Server.ReadTimeout, conf.Server.WriteTimeout)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// loadFromFile reads a configuration from a local file
func (c *configuration) loadFromFile(path string) error {
	var confData []byte
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err = decrypt.Data(data, "yaml")
	if err != nil {
		if err == sops.MetadataNotFound {
			// not an encrypted file
			confData = data
		} else {
			return errors.Wrap(err, "failed to load sops encrypted configuration")
		}
	}
	err = yaml.Unmarshal(confData, &c)
	if err != nil {
		return err
	}
	return nil
}

// newAutographer creates an instance of an autographer
func newAutographer(cachesize int) (a *autographer) {
	var err error
	a = new(autographer)
	a.auths = make(map[string]authorization)
	a.signerIndex = make(map[string]int)
	a.nonces, err = lru.New(cachesize)
	if err != nil {
		log.Fatal(err)
	}
	return a
}

// enableDebug enables debug logging
func (a *autographer) enableDebug() {
	a.debug = true
	return
}

// disableDebug disables debug logging
func (a *autographer) disableDebug() {
	a.debug = false
	return
}

// startCleanupHandler sets up a chan to catch int, kill, term
// signals and run signer AtExit functions
func (a *autographer) startCleanupHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)

	go func() {
		sig := <-c
		log.Infof("main: received signal %s; cleaning up signers", sig)
		for _, s := range a.signers {
			statefulSigner, ok := s.(signer.StatefulSigner)
			if !ok {
				continue
			}
			err := statefulSigner.AtExit()
			if err != nil {
				log.Errorf("main: error in signer %s AtExit fn: %s", s.Config().ID, err)
			}
		}
		os.Exit(0)
	}()
}

// addSigners initializes each signer specified in the configuration by parsing
// and loading their private keys. The signers are then copied over to the
// autographer handler.
func (a *autographer) addSigners(signerConfs []signer.Configuration) error {
	sids := make(map[string]bool)
	for _, signerConf := range signerConfs {
		// forbid signers with the same ID
		if _, exists := sids[signerConf.ID]; exists {
			return fmt.Errorf("duplicate signer ID %q is not permitted", signerConf.ID)
		}
		sids[signerConf.ID] = true
		var (
			s           signer.Signer
			statsClient *signer.StatsClient
			err         error
		)
		if a.stats != nil {
			statsClient, err = signer.NewStatsClient(signerConf, a.stats)
			if statsClient == nil || err != nil {
				return errors.Wrapf(err, "failed to add signer stats client %q or got back nil statsClient", signerConf.ID)
			}
		}
		// give the database handler to the signer configuration
		if a.db != nil {
			signerConf.DB = a.db
		}
		switch signerConf.Type {
		case contentsignature.Type:
			s, err = contentsignature.New(signerConf)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case contentsignaturepki.Type:
			s, err = contentsignaturepki.New(signerConf)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case xpi.Type:
			s, err = xpi.New(signerConf, statsClient)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case apk.Type:
			s, err = apk.New(signerConf)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case mar.Type:
			s, err = mar.New(signerConf)
			if err != nil && strings.HasPrefix(err.Error(), "mar: failed to parse private key: no suitable key found") {
				log.Infof("Skipping signer %q from HSM", signerConf.ID)
				continue
			} else if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case pgp.Type:
			s, err = pgp.New(signerConf)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case gpg2.Type:
			s, err = gpg2.New(signerConf)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		case rsapss.Type:
			s, err = rsapss.New(signerConf)
			if err != nil {
				return errors.Wrapf(err, "failed to add signer %q", signerConf.ID)
			}
		default:
			return fmt.Errorf("unknown signer type %q", signerConf.Type)
		}
		a.signers = append(a.signers, s)
	}
	return nil
}

// addAuthorizations reads a list of authorizations from the configuration and
// stores them into the autographer handler as a map indexed by user id, for fast lookup.
func (a *autographer) addAuthorizations(auths []authorization) (err error) {
	for _, auth := range auths {
		if _, ok := a.auths[auth.ID]; ok {
			return fmt.Errorf("authorization id '" + auth.ID + "' already defined, duplicates are not permitted")
		}
		if auth.HawkTimestampValidity != "" {
			auth.hawkMaxTimestampSkew, err = time.ParseDuration(auth.HawkTimestampValidity)
			if err != nil {
				return err
			}
		} else {
			auth.hawkMaxTimestampSkew = time.Minute
		}
		a.auths[auth.ID] = auth
	}
	return
}

// makeSignerIndex creates a map of authorization IDs and signer IDs to
// quickly locate a signer based on the user requesting the signature.
func (a *autographer) makeSignerIndex() {
	// add an entry for each authid+signerid pair
	for _, auth := range a.auths {
		for _, sid := range auth.Signers {
			for pos, s := range a.signers {
				if sid == s.Config().ID {
					log.Printf("Mapping auth id %q and signer id %q to signer %d with hawk ts validity %s", auth.ID, s.Config().ID, pos, auth.hawkMaxTimestampSkew)
					tag := auth.ID + "+" + s.Config().ID
					a.signerIndex[tag] = pos
				}
			}
		}
	}
	// add a fallback entry with just the authid, to use when no signerid
	// is specified in the signing request. This entry maps to the first
	// authorized signer
	for _, auth := range a.auths {
		// if the authorization has no signer configured, skip it
		if len(auth.Signers) < 1 {
			continue
		}
		for pos, signer := range a.signers {
			if auth.Signers[0] == signer.Config().ID {
				log.Printf("Mapping auth id %q to default signer %d with hawk ts validity %s", auth.ID, pos, auth.hawkMaxTimestampSkew)
				tag := auth.ID + "+"
				a.signerIndex[tag] = pos
				break
			}
		}
	}
}
