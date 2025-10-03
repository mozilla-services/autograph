package database // import "github.com/mozilla-services/autograph/database"

import (
	"database/sql"
	"fmt"
	"time"
)

var (
	// ErrNoSuitableEEFound is returned when no suitable key is found in database
	ErrNoSuitableEEFound = fmt.Errorf("no suitable key found in database")
)

// BeginEndEntityOperations creates a database transaction that locks the endentities table,
// this should be called before doing any lookup or generation operation with endentities.
//
// This global lock will effectively prevent any sort of concurrent operation, which is exactly
// what we want in the case of key generation. Being slow and blocking is OK, risking two
// key generation the happen in parallel is not.
func (db *Handler) BeginEndEntityOperations() (*Transaction, error) {
	// if a db is present, first create a db transaction to lock the row for update
	tx, err := db.Begin()
	if err != nil {
		err = fmt.Errorf("failed to create transaction: %w", err)
		return nil, err
	}
	// lock the table
	_, err = tx.Exec("LOCK TABLE endentities_lock IN ACCESS EXCLUSIVE MODE")
	if err != nil {
		err = fmt.Errorf("failed to lock endentities table: %w", err)
		// We ignore the error from tx.Rollback() because according to the Go documentation,
		// if tx.Rollback() returns an error, the transaction is no longer valid nor
		// committed to the database.
		_ = tx.Rollback()
		return nil, err
	}
	var id uint64
	err = tx.QueryRow(`INSERT INTO endentities_lock(is_locked)
				VALUES ($1) RETURNING id`,
		true).Scan(&id)
	if err != nil {
		_ = tx.Rollback()
		err = fmt.Errorf("failed to lock endentities table: %w", err)
		return nil, err
	}
	return &Transaction{tx, id}, nil
}

// GetLabelOfLatestEE returns the label of the latest end-entity for the specified signer
// that is no older than a given duration
func (db *Handler) GetLabelOfLatestEE(signerID string, youngerThan time.Duration) (label, x5u string, err error) {
	var nullableX5U sql.NullString
	maxAge := time.Now().Add(-youngerThan)
	err = db.QueryRow(`SELECT label, x5u FROM endentities
				WHERE is_current=TRUE AND signer_id=$1 AND created_at > $2
				ORDER BY created_at DESC LIMIT 1`,
		signerID, maxAge).Scan(&label, &nullableX5U)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", ErrNoSuitableEEFound
		}
		return
	}
	x5uValue, err := nullableX5U.Value()
	if x5uValue != nil {
		x5u = x5uValue.(string)
	}
	return
}

// InsertEE uses an existing transaction to insert an end-entity in database
func (tx *Transaction) InsertEE(x5u, label, signerID string) (err error) {
	// hsm_handle is unused, but required to be not null. We should remove this
	// column at some point; in the meantime, we always set it to -1
	_, err = tx.Exec(`INSERT INTO endentities(x5u, label, signer_id, hsm_handle, is_current)
				VALUES ($1, $2, $3, $4, $5)`, x5u, label, signerID, -1, true)
	if err != nil {
		_ = tx.Rollback()
		err = fmt.Errorf("failed to insert new key in database: %w", err)
		return
	}
	// mark all other keys for this signer as no longer current
	_, err = tx.Exec("UPDATE endentities SET is_current=FALSE WHERE signer_id=$1 and label!=$2",
		signerID, label)
	if err != nil {
		err = fmt.Errorf("failed to update is_current status of keys in database: %w", err)
		_ = tx.Rollback()
		return
	}
	return nil
}

// End commits a transaction
func (tx *Transaction) End() error {
	_, err := tx.Exec("UPDATE endentities_lock SET is_locked=FALSE, freed_at=NOW() WHERE id=$1", tx.ID)
	if err != nil {
		err = fmt.Errorf("failed to update is_current status of keys in database: %w", err)
		_ = tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		err = fmt.Errorf("failed to commit transaction in database: %w", err)
		_ = tx.Rollback()
		return err
	}
	return nil
}
