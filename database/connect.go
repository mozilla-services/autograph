package database

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

type Handler struct {
	*sql.DB
}

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
	userPass := url.UserPassword(config.User, config.Password)
	if config.SSLMode == "" {
		config.SSLMode = "disable"
	}
	url := fmt.Sprintf("postgres://%s@%s/%s?sslmode=%s", userPass.String(), config.Host, config.Name, config.SSLMode)
	dbfd, err := sql.Open("postgres", url)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open database connection")
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