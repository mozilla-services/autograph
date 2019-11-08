// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

//go:generate ./version.sh

import (
	"crypto/sha256"
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
	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/apk2"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/contentsignaturepki"
	"go.mozilla.org/autograph/signer/genericrsa"
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
	HSM                      crypto11.PKCS11Config
	Database                 database.Config
	Signers                  []signer.Configuration
	Authorizations           []formats.Authorization
	Monitoring               formats.Authorization
	Heartbeat                heartbeatConfig
	LoadAuthorizationsFromDB bool
}

// An autographer is a running instance of an autograph service,
// with all signers and permissions configured
type autographer struct {
	db            *database.Handler
	stats         *statsd.Client
	signers       []signer.Signer
	auths         map[string]formats.Authorization
	signerIndex   map[string]int
	nonces        *lru.Cache
	debug         bool
	heartbeatConf *heartbeatConfig
}

func main() {
	args := os.Args
	// e.g. when run as 'autograph -c config.yaml' strip leading autograph
	if len(args) > 0 {
		args = os.Args[1:]
	}
	run(parseArgsAndLoadConfig(args))
}

func parseArgsAndLoadConfig(args []string) (conf configuration, listen string, authPrint, authSQL, debug bool) {
	var (
		cfgFile  string
		port     string
		err      error
		logLevel string
		fset     = flag.NewFlagSet("parseArgsAndLoadConfig", flag.ContinueOnError)
	)

	fset.StringVar(&cfgFile, "c", "autograph.yaml", "Path to configuration file")
	fset.StringVar(&port, "p", "", "Port to listen on. Overrides the listen var from the config file")
	fset.BoolVar(&authPrint, "A", false, "Print authorizations matrix and exit")
	fset.BoolVar(&authSQL, "auth-to-sql", false, "Print authorizations as SQL to stdout")
	// https://github.com/sirupsen/logrus#level-logging
	fset.StringVar(&logLevel, "l", "", "Set the logging level. Optional defaulting to info. Options: trace, debug, info, warning, error, fatal and panic")
	fset.BoolVar(&debug, "D", false, "Sets the log level to debug to print debug logs.")
	fset.Parse(args)

	switch logLevel {
	case "debug":
		debug = true
	case "":
		if debug {
			logLevel = "debug"
		}
	default:
		if debug {
			log.Fatalf("Got debug true, but conflicting log level: %s", logLevel)
		}
	}
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			log.Fatalf("Error parsing log level: %s", err)
		}
		log.SetLevel(level)
		log.Infof("Set logging level to %s", level)
	}

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

func run(conf configuration, listen string, authPrint, authSQL, debug bool) {
	var (
		ag    *autographer
		err   error
		auths []formats.Authorization = conf.Authorizations
	)

	if authSQL {
		ag.PrintConfAuthorizationsAsSQL(conf)
		os.Exit(0)
	}

	// initialize signers from the configuration
	// and store them into the autographer handler
	ag = newAutographer(conf.Server.NonceCacheSize)
	ag.heartbeatConf = &conf.Heartbeat

	if conf.isDBEnabled() {
		// ignore the monitor close chan since it will stop
		// when the app is stopped
		_ = ag.addDB(conf.Database)
	}

	// initialize the hsm if a configuration is defined
	if conf.HSM.Path != "" {
		ag.initHSM(conf)
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

	if conf.LoadAuthorizationsFromDB {
		if len(conf.Authorizations) > 0 {
			log.Fatalf("Cannot load authorizations from the DB and config file")
		}
		if ag.db == nil {
			log.Fatalf("Failed load authorizations from the DB: db handler is nil")
		}
		auths, err = ag.db.GetAuthorizations()
		if err != nil {
			log.Fatalf("Failed to load authorizations from the DB: %s", err)
		}
		log.Infof("Loaded %d authorizations from the DB", len(auths))
	}
	err = ag.addAuthorizations(auths)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.addMonitoring(conf.Monitoring)
	if err != nil {
		log.Fatal(err)
	}
	err = ag.makeSignerIndex()
	if err != nil {
		log.Fatal(err)
	}
	if debug {
		ag.enableDebug()
	}

	if authPrint {
		ag.PrintAuthorizations()
		os.Exit(0)
	}

	ag.startCleanupHandler()

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/__heartbeat__", ag.handleHeartbeat).Methods("GET")
	router.HandleFunc("/__lbheartbeat__", handleLBHeartbeat).Methods("GET")
	router.HandleFunc("/__version__", handleVersion).Methods("GET")
	router.HandleFunc("/__monitor__", ag.handleMonitor).Methods("GET")
	router.HandleFunc("/sign/file", ag.handleSignature).Methods("POST")
	router.HandleFunc("/sign/data", ag.handleSignature).Methods("POST")
	router.HandleFunc("/sign/hash", ag.handleSignature).Methods("POST")
	if os.Getenv("AUTOGRAPH_PROFILE") == "1" {
		err = setRuntimeConfig()
		if err != nil {
			log.Fatal(err)
		}
		addProfilerHandlers(router)
		log.Infof("enabled HTTP perf profiler")
	}

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
	var (
		data, confData []byte
		confSHA        [32]byte
		err            error
	)
	data, err = ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	confSHA = sha256.Sum256(data)

	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err = decrypt.Data(data, "yaml")
	if err == nil {
		log.Infof("loaded encrypted config from %s with sha256sum %x", path, confSHA)
	} else if err == sops.MetadataNotFound {
		log.Infof("loaded unencrypted config from %s with sha256sum %x", path, confSHA)
		// not an encrypted file
		confData = data
	} else {
		return errors.Wrap(err, "failed to load sops encrypted configuration")
	}

	err = yaml.Unmarshal(confData, &c)
	if err != nil {
		return err
	}

	if c.Heartbeat.DBCheckTimeout == time.Duration(int64(0)) || c.Heartbeat.HSMCheckTimeout == time.Duration(int64(0)) {
		return errors.Errorf("Missing required heartbeat config section with non-zero timeouts")
	}
	return nil
}

// isDBEnabled returns whether the database is enabled in the config
func (c *configuration) isDBEnabled() bool {
	return c.Database.Name != ""
}

// newAutographer creates an instance of an autographer
func newAutographer(cachesize int) (a *autographer) {
	var err error
	a = new(autographer)
	a.auths = make(map[string]formats.Authorization)
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

// addDB connects to the DB and starts a gorountine to monitor DB
// connectivity
func (a *autographer) addDB(dbConf database.Config) chan bool {
	var err error
	a.db, err = database.Connect(dbConf)
	if err != nil {
		log.Fatal(err)
	}
	if a.db == nil {
		log.Fatal("failed to initialize database connection, unknown error")
	}
	// start a monitoring function that errors if the db
	// becomes inaccessible
	closeDBMonitor := make(chan bool, 1)
	go a.db.Monitor(dbConf.MonitorPollInterval, closeDBMonitor)
	log.Print("database connection established")
	return closeDBMonitor
}

// initHSM sets up the HSM and notifies signers it is available
func (a *autographer) initHSM(conf configuration) {
	tmpCtx, err := crypto11.Configure(&conf.HSM)
	if err != nil {
		log.Fatal(err)
	}
	if tmpCtx != nil {
		// if we successfully initialized the crypto11 context,
		// tell the signers they can try using the HSM
		for i := range conf.Signers {
			conf.Signers[i].InitHSM(tmpCtx)
			signerConf := conf.Signers[i]

			// save the first signer with an HSM label as
			// the key to test from the heartbeat handler
			if a.heartbeatConf != nil && a.heartbeatConf.hsmSignerConf == nil && !signerConf.PrivateKeyHasPEMPrefix() {
				a.heartbeatConf.hsmSignerConf = &signerConf
			}
		}
	}
}

// addSigners initializes each signer specified in the configuration by parsing
// and loading their private keys. The signers are then copied over to the
// autographer handler.
func (a *autographer) addSigners(signerConfs []signer.Configuration) error {
	sids := make(map[string]bool)
	for _, signerConf := range signerConfs {
		if err := formats.ValidateSignerID(signerConf.ID); err != nil {
			return fmt.Errorf("signer ID %q does not match the permitted format %q",
				signerConf.ID, formats.SignerIDFormat)
		}
		// forbid signers with the same ID
		if _, exists := sids[signerConf.ID]; exists {
			return fmt.Errorf("duplicate signer ID %q is not permitted", signerConf.ID)
		}
		// "monitor" is a reserved name
		if signerConf.ID == "monitor" {
			return fmt.Errorf("'monitor' is a reserved signer name and cannot be used in configuration")
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
		case apk2.Type:
			s, err = apk2.New(signerConf)
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
		case genericrsa.Type:
			s, err = genericrsa.New(signerConf)
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
func (a *autographer) addAuthorizations(auths []formats.Authorization) (err error) {
	for _, auth := range auths {
		if _, ok := a.auths[auth.ID]; ok {
			return fmt.Errorf("authorization id '" + auth.ID + "' already defined, duplicates are not permitted")
		}
		if auth.HawkTimestampValidity <= 0*time.Second {
			auth.HawkTimestampValidity = time.Minute
		}
		a.auths[auth.ID] = auth
	}
	return
}

// makeSignerIndex creates a map of authorization IDs and signer IDs to
// quickly locate a signer based on the user requesting the signature.
func (a *autographer) makeSignerIndex() error {
	// add an entry for each authid+signerid pair
	for id, auth := range a.auths {
		if id == "monitor" {
			// the "monitor" authorization is a special case
			// that doesn't need a signer index
			continue
		}
		// if the authorization has no signer configured, error out
		if len(auth.Signers) < 1 {
			return fmt.Errorf("auth id %q must have at least one signer configured", id)
		}
		for _, sid := range auth.Signers {
			// make sure the sid is valid
			sidExists := false

			for pos, s := range a.signers {
				if sid == s.Config().ID {
					sidExists = true
					log.Printf("Mapping auth id %q and signer id %q to signer %d with hawk ts validity %s", auth.ID, s.Config().ID, pos, auth.HawkTimestampValidity)
					tag := auth.ID + "+" + s.Config().ID
					a.signerIndex[tag] = pos
				}
			}

			if !sidExists {
				return fmt.Errorf("in auth id %q, signer id %q was not found in the list of known signers", auth.ID, sid)
			}
		}
		// add a default entry for the signer, such that if none is provided in
		// the signing request, the default is used
		for pos, signer := range a.signers {
			if auth.Signers[0] == signer.Config().ID {
				log.Printf("Mapping auth id %q to default signer %d with hawk ts validity %s", auth.ID, pos, auth.HawkTimestampValidity)
				tag := auth.ID + "+"
				a.signerIndex[tag] = pos
				break
			}
		}
	}
	return nil
}
