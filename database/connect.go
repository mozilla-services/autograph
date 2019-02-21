package database // import "go.mozilla.org/autograph/database"

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	// lib/pq is the postgres driver
	_ "github.com/lib/pq"

	"github.com/pkg/errors"
)

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
	Name         string
	User         string
	Password     string
	Host         string
	SSLMode      string
	MaxOpenConns int
	MaxIdleConns int
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
		dsn = fmt.Sprintf("postgres://%s@%s/%s?sslmode=%s",
			userPass.String(), config.Host, config.Name, config.SSLMode)
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

// Monitor runs an infinite loop that queries the database every 10 seconds
// and panics if the query fails. It can be used in a goroutine to crash when
// the database becomes unavailable.
func (db *Handler) Monitor() {
	// simple DB watchdog, crashes the process if connection dies
	for {
		var one uint
		err := db.QueryRow("SELECT 1").Scan(&one)
		if err != nil {
			log.Fatal("Database connection failed:", err)
		}
		if one != 1 {
			log.Fatal("Apparently the database doesn't know the meaning of one anymore. Crashing.")
		}
		time.Sleep(10 * time.Second)
	}
}
