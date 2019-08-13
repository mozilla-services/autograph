package database // import "go.mozilla.org/autograph/database"

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

	"github.com/pkg/errors"
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
	Name                string
	User                string
	Password            string
	Host                string
	SSLMode             string
	SSLRootCert         string
	MaxOpenConns        int
	MaxIdleConns        int
	MonitorPollInterval time.Duration
}

// Connect creates a database connection and returns a handler
func Connect(config Config) (*Handler, error) {
	var dsn string
	if os.Getenv("AUTOGRAPH_DB_DSN") != "" {
		dsn = os.Getenv("AUTOGRAPH_DB_DSN")
	} else {
		userPass := url.UserPassword(config.User, config.Password)
		if config.SSLMode == "" {
			config.SSLMode = "disable"
		}
		dsn = fmt.Sprintf("postgres://%s@%s/%s?sslmode=%s&sslrootcert=%s",
			userPass.String(), config.Host, config.Name, config.SSLMode, config.SSLRootCert)
	}
	dbfd, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open database connection")
	}
	if config.MaxOpenConns > 0 {
		dbfd.SetMaxOpenConns(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		dbfd.SetMaxIdleConns(config.MaxIdleConns)
	}
	return &Handler{dbfd}, nil
}

// CheckConnectionContext runs a test query against the database and
// returns an error if it fails
func (db *Handler) CheckConnectionContext(ctx context.Context) error {
	var one uint
	err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
	if err != nil {
		return errors.Wrap(err, "Database connection failed")
	}
	if one != 1 {
		return errors.Errorf("Apparently the database doesn't know the meaning of one anymore")
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
				break
			}
		case <-quit:
			log.Info("Shutting down DB monitor")
			return
		}
	}
}
