package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNoSuitableEEFound = errors.New("no suitable key found in database")
)

// GetLabelOfLatestEE returns the label of the latest end-entity for the specified signer
// that is no older than a given duration
func (db *Handler) GetLabelOfLatestEE(signerId string, youngerThan time.Duration) (label, x5u string, err error) {
	var nullableX5U sql.NullString
	maxAge := time.Now().Add(-youngerThan)
	err = db.QueryRow(`SELECT label, x5u FROM endentities
				WHERE is_current=TRUE AND signer_id=$1 AND created_at > $2
				ORDER BY created_at DESC LIMIT 1`,
		signerId, maxAge).Scan(&label, &nullableX5U)
	if err == sql.ErrNoRows {
		return "", "", ErrNoSuitableEEFound
	}
	x5uValue, err := nullableX5U.Value()
	if x5uValue != nil {
		x5u = x5uValue.(string)
	}
	return
}

// UpdateX5U updates the value of an x5u for a given end entity
func (db *Handler) UpdateX5U(x5u, label, signerId string) (err error) {
	res, err := db.Exec(`UPDATE endentities SET x5u=$1
	  		   	WHERE is_current=TRUE AND label=$2 AND signer_id=$3`,
		x5u, label, signerId)
	if err != nil {
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return
	}
	if rowsAffected != 1 {
		return fmt.Errorf("expected to updated 1 row but updated %d instead", rowsAffected)
	}
	return
}
