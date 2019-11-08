package database // import "go.mozilla.org/autograph/database"

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
	"github.com/pkg/errors"

	"go.mozilla.org/autograph/formats"
)

var (
	// ErrNoSuitableEEFound is returned when no suitable key is found in database
	ErrNoSuitableEEFound = errors.New("no suitable key found in database")
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
		err = errors.Wrap(err, "failed to create transaction")
		return nil, err
	}
	// lock the table
	_, err = tx.Exec("LOCK TABLE endentities_lock IN ACCESS EXCLUSIVE MODE")
	if err != nil {
		err = errors.Wrap(err, "failed to lock endentities table")
		tx.Rollback()
		return nil, err
	}
	var id uint64
	err = tx.QueryRow(`INSERT INTO endentities_lock(is_locked)
				VALUES ($1) RETURNING id`,
		true).Scan(&id)
	if err != nil {
		tx.Rollback()
		err = errors.Wrap(err, "failed to lock endentities table")
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
	if err == sql.ErrNoRows {
		return "", "", ErrNoSuitableEEFound
	}
	x5uValue, err := nullableX5U.Value()
	if x5uValue != nil {
		x5u = x5uValue.(string)
	}
	return
}

// InsertEE uses an existing transaction to insert an end-entity in database
func (tx *Transaction) InsertEE(x5u, label, signerID string, hsmHandle uint) (err error) {
	_, err = tx.Exec(`INSERT INTO endentities(x5u, label, signer_id, hsm_handle, is_current)
				VALUES ($1, $2, $3, $4, $5)`, x5u, label, signerID, hsmHandle, true)
	if err != nil {
		tx.Rollback()
		err = errors.Wrap(err, "failed to insert new key in database")
		return
	}
	// mark all other keys for this signer as no longer current
	_, err = tx.Exec("UPDATE endentities SET is_current=FALSE WHERE signer_id=$1 and label!=$2",
		signerID, label)
	if err != nil {
		err = errors.Wrap(err, "failed to update is_current status of keys in database")
		tx.Rollback()
		return
	}
	return nil
}

// End commits a transaction
func (tx *Transaction) End() error {
	_, err := tx.Exec("UPDATE endentities_lock SET is_locked=FALSE, freed_at=NOW() WHERE id=$1", tx.ID)
	if err != nil {
		err = errors.Wrap(err, "failed to update is_current status of keys in database")
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "failed to commit transaction in database")
		tx.Rollback()
		return err
	}
	return nil
}

const selectAuths = `SELECT
hawk_credentials.id as hawk_id,
hawk_credentials.secret as hawk_secret,
EXTRACT(EPOCH FROM hawk_credentials.validity) as hawk_validity,
array_agg(signers.id) AS signer_ids
FROM
authorizations
INNER JOIN hawk_credentials ON authorizations.credential_id = hawk_credentials.id
INNER JOIN signers ON authorizations.signer_id = signers.id
GROUP BY hawk_credentials.id`

// GetAuthorizations returns the hawk credentials and validity and any authorized signer IDs
func (db *Handler) GetAuthorizations() (auths []formats.Authorization, err error) {
	rows, err := db.Query(selectAuths)
	if err != nil {
		err = errors.Wrapf(err, "Error selecting auths")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var (
			auth    formats.Authorization
			seconds int64
		)
		if err = rows.Scan(&auth.ID, &auth.Key, &seconds, pq.Array(&auth.Signers)); err != nil {
			err = errors.Wrapf(err, "Error scanning auth row")
			return
		}
		auth.HawkTimestampValidity = time.Duration(seconds) * time.Second
		auths = append(auths, auth)
	}
	if err = rows.Err(); err != nil {
		err = errors.Wrapf(err, "Error after iterating over auth rows")
		return
	}
	return
}

// InsertAuthorization creates inserts a hawk credential w/ validity,
// authorized signer IDs, and permissions to access the signers for
// the creds
func (db *Handler) InsertAuthorization(auth formats.Authorization) (err error) {
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		err = errors.Wrap(err, "failed to create transaction")
		return err
	}

	_, err = tx.Exec(`INSERT INTO hawk_credentials(id, secret, validity)
				VALUES ($1, $2, $3)`, &auth.ID, &auth.Key, auth.HawkTimestampValidity.Seconds())
	if err != nil {
		tx.Rollback()
		err = errors.Wrapf(err, "failed to insert hawk creds for id %s", auth.ID)
		return err
	}
	for _, signerID := range auth.Signers {
		_, err = tx.Exec(`INSERT INTO signers(id) VALUES ($1)`, signerID)
		if err != nil {
			tx.Rollback()
			err = errors.Wrapf(err, "failed to insert signer id %s", signerID)
			return err
		}
		_, err = tx.Exec(`INSERT INTO authorizations(credential_id, signer_id) VALUES ($1, $2)`, auth.ID, signerID)
		if err != nil {
			tx.Rollback()
			err = errors.Wrapf(err, "failed to insert signer id %s", signerID)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "failed to commit transaction in database")
		tx.Rollback()
		return err
	}
	return
}
