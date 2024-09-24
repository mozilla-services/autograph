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
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	lru "github.com/hashicorp/golang-lru"

	"github.com/mozilla-services/yaml"

	"github.com/mozilla-services/autograph/database"
	"github.com/mozilla-services/autograph/signer"
	"github.com/mozilla-services/autograph/signer/apk2"
	"github.com/mozilla-services/autograph/signer/contentsignature"
	"github.com/mozilla-services/autograph/signer/contentsignaturepki"
	"github.com/mozilla-services/autograph/signer/genericrsa"
	"github.com/mozilla-services/autograph/signer/gpg2"
	"github.com/mozilla-services/autograph/signer/mar"
	"github.com/mozilla-services/autograph/signer/xpi"

	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/mozilla-services/autograph/crypto11"
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
	HSM                   crypto11.PKCS11Config
	Database              database.Config
	Signers               []signer.Configuration
	Authorizations        []authorization
	Monitoring            authorization
	Heartbeat             heartbeatConfig
	HawkTimestampValidity string
	MonitorInterval       time.Duration
}

// An autographer is a running instance of an autograph service,
// with all signers and permissions configured
type autographer struct {
	db                   *database.Handler
	stats                statsd.ClientInterface
	nonces               *lru.Cache
	debug                bool
	heartbeatConf        *heartbeatConfig
	authBackend          authBackend
	hawkMaxTimestampSkew time.Duration

	// Used to signal the monitor on exit of the autographer instance.
	exit chan interface{}
}

func main() {
	args := os.Args
	// e.g. when run as 'autograph -c config.yaml' strip leading autograph
	if len(args) > 0 {
		args = os.Args[1:]
	}
	run(parseArgsAndLoadConfig(args))
}

func parseArgsAndLoadConfig(args []string) (conf configuration, listen string, debug bool) {
	var (
		cfgFile  string
		port     string
		err      error
		logLevel string
		fset     = flag.NewFlagSet("parseArgsAndLoadConfig", flag.ContinueOnError)
	)

	fset.StringVar(&cfgFile, "c", "autograph.yaml", "Path to configuration file")
	fset.StringVar(&port, "p", "", "Port to listen on. Overrides the listen var from the config file")
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

func run(conf configuration, listen string, debug bool) {
	var (
		ag  *autographer
		err error
	)

	// initialize signers from the configuration
	// and store them into the autographer handler
	ag = newAutographer(conf.Server.NonceCacheSize)
	ag.heartbeatConf = &conf.Heartbeat

	if conf.Database.Name != "" {
		// ignore the monitor close chan since it will stop
		// when the app is stopped
		_ = ag.addDB(conf.Database)
	}

	// initialize the hsm if a configuration is defined
	if conf.HSM.Path != "" {
		err = ag.initHSM(conf)
		if err != nil {
			log.Fatalf("main.run: %s", err)
		}
	}

	err = ag.addStats(conf)
	if err != nil {
		log.Fatal(err)
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
	if conf.HawkTimestampValidity != "" {
		ag.hawkMaxTimestampSkew, err = time.ParseDuration(conf.HawkTimestampValidity)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		ag.hawkMaxTimestampSkew = time.Minute
	}
	log.Infof("setting hawk timestamp skew to %s", ag.hawkMaxTimestampSkew)

	if debug {
		ag.enableDebug()
	}

	ag.startCleanupHandler()

	// Initialize a monitor.
	monitor := newMonitor(ag, conf.MonitorInterval)

	stats := ag.stats

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/__heartbeat__", statsMiddleware(ag.handleHeartbeat, "http.nonapi.heartbeat", stats)).Methods("GET")
	router.HandleFunc("/__lbheartbeat__", statsMiddleware(handleLBHeartbeat, "http.nonapi.lbheartbeat", stats)).Methods("GET")
	router.HandleFunc("/__version__", statsMiddleware(handleVersion, "http.nonapi.version", stats)).Methods("GET")
	router.HandleFunc("/__monitor__", statsMiddleware(monitor.handleMonitor, "http.nonapi.monitor", stats)).Methods("GET")
	router.HandleFunc("/sign/files", apiStatsMiddleware(ag.handleSignature, "http.api.sign/files", stats)).Methods("POST")
	router.HandleFunc("/sign/file", apiStatsMiddleware(ag.handleSignature, "http.api.sign/file", stats)).Methods("POST")
	router.HandleFunc("/sign/data", apiStatsMiddleware(ag.handleSignature, "http.api.sign/data", stats)).Methods("POST")
	router.HandleFunc("/sign/hash", apiStatsMiddleware(ag.handleSignature, "http.api.sign/hash", stats)).Methods("POST")
	router.HandleFunc("/auths/{auth_id:[a-zA-Z0-9-_]{1,255}}/keyids", apiStatsMiddleware(ag.handleGetAuthKeyIDs, "http.api.getauthkeyids", stats)).Methods("GET")
	if os.Getenv("AUTOGRAPH_PROFILE") == "1" {
		err = setRuntimeConfig()
		if err != nil {
			log.Fatal(err)
		}
		addProfilerHandlers(router)
		log.Infof("enabled HTTP perf profiler")
	}

	// For each signer with a local chain upload location (eg: using the file
	// scheme) create an handler to serve that directory at the path /x5u/keyid/
	for _, signerConf := range conf.Signers {
		parsedURL, err := url.Parse(signerConf.X5U)
		if err != nil || parsedURL.Scheme != "file" {
			// This signer doesn't upload certificate chains to local storage.
			continue
		}

		prefix := fmt.Sprintf("/x5u/%s/", signerConf.ID)
		router.PathPrefix(prefix).Handler(http.StripPrefix(prefix, http.FileServer(http.Dir(parsedURL.Path))))
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

	// Shutdown the monitor.
	close(ag.exit)
}

// loadFromFile reads a configuration from a local file
func (c *configuration) loadFromFile(path string) error {
	var (
		data, confData []byte
		confSHA        [32]byte
		err            error
	)
	data, err = os.ReadFile(path)
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
		return fmt.Errorf("failed to load sops encrypted configuration: %w", err)
	}

	err = yaml.Unmarshal(confData, &c)
	if err != nil {
		return err
	}

	if c.Heartbeat.DBCheckTimeout == time.Duration(int64(0)) || c.Heartbeat.HSMCheckTimeout == time.Duration(int64(0)) {
		return fmt.Errorf("missing required heartbeat config section with non-zero timeouts")
	}
	return nil
}

// newAutographer creates an instance of an autographer
func newAutographer(cachesize int) (a *autographer) {
	var err error
	a = new(autographer)
	a.authBackend = newInMemoryAuthBackend()
	a.nonces, err = lru.New(cachesize)
	a.exit = make(chan interface{})
	a.stats = &statsd.NoOpClient{}
	if err != nil {
		log.Fatal(err)
	}
	return a
}

// enableDebug enables debug logging
func (a *autographer) enableDebug() {
	a.debug = true
}

// disableDebug disables debug logging
func (a *autographer) disableDebug() {
	a.debug = false
}

// getAuthByID returns an authorization if it exists or nil. Call
// addAuthorizations and addMonitoring first
func (a *autographer) getAuthByID(id string) (authorization, error) {
	return a.authBackend.getAuthByID(id)
}

// startCleanupHandler sets up a chan to catch int, kill, term
// signals and run signer AtExit functions
func (a *autographer) startCleanupHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-c
		log.Infof("main: received signal %s; cleaning up signers", sig)
		for _, s := range a.getSigners() {
			statefulSigner, ok := s.(signer.StatefulSigner)
			if !ok {
				continue
			}
			err := statefulSigner.AtExit()
			if err != nil {
				log.Errorf("main: error in signer %s AtExit fn: %s", s.Config().ID, err)
			}
		}

		// Shutdown the monitor
		close(a.exit)

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
func (a *autographer) initHSM(conf configuration) error {
	tmpCtx, err := crypto11.Configure(&conf.HSM, crypto11.NewDefaultPKCS11Context)
	if err != nil {
		return fmt.Errorf("error in initHSM from crypto11.Configure: %w", err)
	}
	if tmpCtx != nil {
		// if we successfully initialized the crypto11 context,
		// tell the signers they can try using the HSM
		for i := range conf.Signers {
			// These two lines are strange and required until we fix how we use
			// `signer.Configuration`. Since this list of
			// `singer.Configuration`s is only of structs (not pointers), and
			// since we're modifying the fields of those structs within
			// `InitHSM` and also using this conf.Signers list elsewhere
			// (including some failed attempts at copying the structs), we have
			// to ensure the `InitHSM` the modifications stick by referencing
			// the `Configuration`s through this slice. Without this
			// `Signers[i]` call, you'll get mysterious failures where keys
			// can't be found in the HSM.
			//
			// TODO(AUT-203): when we make `signer.Configuration` immutable,
			// we'll not need this strange `conf.Signers[i]` and can loop
			// through them normally.
			conf.Signers[i].InitHSM(signer.NewAWSHSM(tmpCtx))
			signerConf := &conf.Signers[i]

			if signerConf.PrivateKeyHasPEMPrefix() {
				// If the private key is not stored in the HSM, we have nothing
				// more to do.
				continue
			}

			// save the first signer with an HSM label as
			// the key to test from the heartbeat handler
			if a.heartbeatConf != nil && a.heartbeatConf.hsmSignerConf == nil {
				a.heartbeatConf.hsmSignerConf = signerConf

				err := signerConf.CheckHSMConnection()
				if err != nil {
					return fmt.Errorf("hsm connection check failed during initHSM on signer id %#v: %w", signerConf.ID, err)
				}
			}
		}
	}
	return nil
}

// addSigners initializes each signer specified in the configuration by parsing
// and loading their private keys. The signers are then copied over to the
// autographer handler.
func (a *autographer) addSigners(signerConfs []signer.Configuration) error {
	sids := make(map[string]bool)
	for _, signerConf := range signerConfs {
		if !regexp.MustCompile(signer.IDFormat).MatchString(signerConf.ID) {
			return fmt.Errorf("signer ID %q does not match the permitted format %q",
				signerConf.ID, signer.IDFormat)
		}
		// forbid signers with the same ID
		if _, exists := sids[signerConf.ID]; exists {
			return fmt.Errorf("duplicate signer ID %q is not permitted", signerConf.ID)
		}
		// "monitor" is a reserved name
		if signerConf.ID == monitorAuthID {
			return fmt.Errorf("'monitor' is a reserved signer name and cannot be used in configuration")
		}
		sids[signerConf.ID] = true
		var (
			s           signer.Signer
			statsClient *signer.StatsClient
			err         error
		)
		statsClient, err = signer.NewStatsClient(signerConf, a.stats)
		if statsClient == nil || err != nil {
			return fmt.Errorf("failed to add signer stats client %q or got back nil statsClient: %w", signerConf.ID, err)
		}
		// give the database handler to the signer configuration
		if a.db != nil {
			signerConf.DB = a.db
		}
		switch signerConf.Type {
		case contentsignature.Type:
			s, err = contentsignature.New(signerConf)
			if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		case contentsignaturepki.Type:
			s, err = contentsignaturepki.New(signerConf)
			if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		case xpi.Type:
			s, err = xpi.New(signerConf, statsClient)
			if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		case apk2.Type:
			s, err = apk2.New(signerConf)
			if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		case mar.Type:
			s, err = mar.New(signerConf)
			if err != nil && strings.HasPrefix(err.Error(), "mar: failed to parse private key: no suitable key found") {
				log.Infof("Skipping signer %q from HSM", signerConf.ID)
				continue
			} else if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		case gpg2.Type:
			tmpDirPrefix := fmt.Sprintf("autograph_%s_%s_%s_", signerConf.Type, signerConf.KeyID, signerConf.Mode)
			s, err = gpg2.New(signerConf, tmpDirPrefix)
			if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		case genericrsa.Type:
			s, err = genericrsa.New(signerConf)
			if err != nil {
				return fmt.Errorf("failed to add signer %q: %w", signerConf.ID, err)
			}
		default:
			return fmt.Errorf("unknown signer type %q", signerConf.Type)
		}
		a.addSigner(s)
	}
	return nil
}

// addMonitoring adds an authorization to enable the
// tools/autograph-monitor
func (a *autographer) addMonitoring(auth authorization) (err error) {
	if auth.Key == "" {
		log.Infof("monitoring is disabled. No key found")
		return nil
	}
	return a.authBackend.addMonitoringAuth(auth.Key)
}

// addAuthorizations reads a list of authorizations from the configuration and
// stores them into the autographer handler as a map indexed by user id, for fast lookup.
func (a *autographer) addAuthorizations(auths []authorization) (err error) {
	for _, auth := range auths {
		err = a.authBackend.addAuth(&auth)
		if err != nil {
			return
		}
	}
	return
}

// getSigners returns the slice of configured signers
func (a *autographer) getSigners() []signer.Signer {
	return a.authBackend.getSigners()
}

// addSigner adds a configured signer
func (a *autographer) addSigner(signer signer.Signer) {
	a.authBackend.addSigner(signer)
}
