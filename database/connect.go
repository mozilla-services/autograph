package database // import "github.com/mozilla-services/autograph/database"

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"

	// lib/pq is the postgres driver
	_ "github.com/lib/pq"
)

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph")
}

// Handler handles a database connection
type Handler struct {
	*sql.DB
}

// Transaction owns a sql transaction
type Transaction struct {
	*sql.Tx
	ID uint64
}

// Config holds the parameters to connect to a database
type Config struct {
	Name        string
	User        string
	Password    string
	Host        string
	SSLMode     string
	SSLRootCert string
	// SSLRootCertificates is a list of root certificates to attempt to verify
	// the TLS connection to the PostgreSQL database with. These will be tried
	// in the order they are listed. This is useful when the database server
	// needs to rotate its keys.
	SSLRootCertificates []string `yaml:"sslrootcertificates"` // Matching the no-underscore style elsewhere
	MaxOpenConns        int
	MaxIdleConns        int
	MonitorPollInterval time.Duration
}

// Connect creates a database connection and returns a handler
func Connect(config Config) (*Handler, error) {
	dsns := constructDSNStrings(config)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var outerErr error
	for _, dsn := range dsns {
		h, err := connect(ctx, config, dsn)
		if err == nil {
			return h, nil
		}
		outerErr = err
	}
	return nil, outerErr
}

// dsnString is a PostgreSQL database connection string. It's mostly to prevent
// the internal API here being too stringly-typed.
type dsnString string

// construcDSNStrings returns a list of DSN strings to try connecting to the
// PostgreSQL database with. If an AUTOGRAPH_DB_DSN env var is set, the list
// will contain only it. Otherwise, it will create a DSN for each certificate
// that autograph is configured to try when verifiying the TLS connection. This
// is to allow us to switch to a new AWS RDS certificate without extended
// downtime.
func constructDSNStrings(config Config) []dsnString {
	if os.Getenv("AUTOGRAPH_DB_DSN") != "" {
		return []dsnString{dsnString(os.Getenv("AUTOGRAPH_DB_DSN"))}
	}
	var rootCerts []string
	if config.SSLRootCert != "" {
		rootCerts = append(rootCerts, config.SSLRootCert)
	}
	rootCerts = append(rootCerts, config.SSLRootCertificates...)
	var dsns []dsnString
	for _, rootCert := range rootCerts {
		userPass := url.UserPassword(config.User, config.Password)
		if config.SSLMode == "" {
			config.SSLMode = "disable"
		}
		dsn := fmt.Sprintf("postgres://%s@%s/%s?sslmode=%s&sslrootcert=%s",
			userPass.String(), config.Host, config.Name, config.SSLMode, rootCert)
		dsns = append(dsns, dsnString(dsn))
	}
	return dsns
}

func connect(ctx context.Context, config Config, dsn dsnString) (*Handler, error) {
	dbfd, err := sql.Open("postgres", string(dsn))
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	if config.MaxOpenConns > 0 {
		dbfd.SetMaxOpenConns(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		dbfd.SetMaxIdleConns(config.MaxIdleConns)
	}
	h := &Handler{dbfd}
	dbCheckCtx, dbCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dbCancel()
	err = h.CheckConnectionContext(dbCheckCtx)
	return h, err
}

// CheckConnectionContext runs a test query against the database and
// returns an error if it fails
func (db *Handler) CheckConnectionContext(ctx context.Context) error {
	var one uint
	err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("apparently the database doesn't know the meaning of one anymore")
	}
	return nil
}

// Monitor queries the database every pollInterval until it gets a
// quit signal logging an error when the test query fails. It can be
// used in a goroutine to check when the database becomes unavailable.
func (db *Handler) Monitor(pollInterval time.Duration, quit chan bool) {
	log.Infof("starting DB monitor polling every %s", pollInterval)
	for {
		select {
		case <-time.After(pollInterval):
			err := db.CheckConnectionContext(context.Background())
			if err != nil {
				log.Error(err)
			}
		case <-quit:
			log.Info("Shutting down DB monitor")
			return
		}
	}
}

// GetTestDBHost returns the env var AUTOGRAPH_DB_HOST value or default of
// 127.0.0.1
func GetTestDBHost() string {
	host, ok := os.LookupEnv("AUTOGRAPH_DB_HOST")
	if !ok {
		host = "127.0.0.1"
		log.Printf("Using default AUTOGRAPH_DB_HOST=%s", host)
	} else {
		log.Printf("Using AUTOGRAPH_DB_HOST=%s", host)
	}
	return host
}
