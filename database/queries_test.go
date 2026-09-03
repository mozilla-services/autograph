package database

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestConcurrentEndEntityOperations(t *testing.T) {
	host := GetTestDBHost()
	db, err := Connect(Config{
		Name:                "autograph",
		User:                "myautographdbuser",
		Password:            "myautographdbpassword",
		Host:                host + ":5432",
		MonitorPollInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	var one uint
	err = db.QueryRow("SELECT 1").Scan(&one)
	if err != nil || one != 1 {
		t.Fatal("Database connection failed:", err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	concurrency := 73 // took a long time to pick that number!
	wg.Add(concurrency)
	signerID := fmt.Sprintf("database_unit_testing_%d", time.Now().UnixNano())
	labelsSyncMap := sync.Map{}

	for i := 0; i < concurrency; i++ {
		go func(j int) {
			label := waitAndMakeEE(j, db, &wg, t, signerID)
			labelsSyncMap.Store(label, true)
		}(i)
	}
	wg.Wait()
	labels := make(map[string]bool)

	labelsSyncMap.Range(func(key, value interface{}) bool {
		labels[key.(string)] = true
		return true
	})
	if len(labels) != 1 {
		t.Fatalf("expected to find a single label but found %d: %s",
			len(labels), reflect.ValueOf(labels).MapKeys())
	}
	t.Logf("successfully returned a single label %q for all %d goroutines",
		reflect.ValueOf(labels).MapKeys(), concurrency)
}

func waitAndMakeEE(j int, db *Handler, wg *sync.WaitGroup, t *testing.T, signerID string) string {
	defer wg.Done()
	t.Logf("TestConcurrentEndEntityOperations: starting routine %d", j)

	label, _, err := db.GetLabelOfLatestEE(signerID, 15*time.Second)
	switch err {
	case ErrNoSuitableEEFound:
		tx, err := db.BeginEndEntityOperations()
		if err != nil {
			t.Fatalf("failed to begin end-entity db operations: %v", err)
		}
		// test again the no EE is available after obtaining the lock, just in
		// case another routine made an EE in the meantime
		label, _, err = db.GetLabelOfLatestEE(signerID, 15*time.Second)
		switch err {
		case nil:
			t.Logf("TestConcurrentEndEntityOperations: routine %d is returning end-entity %q", j, label)
			goto releaseLock
		case ErrNoSuitableEEFound:
			break
		default:
			t.Fatal(err)
		}
		// make a new EE
		label = fmt.Sprintf("%d", time.Now().UnixNano())
		t.Logf("TestConcurrentEndEntityOperations: routine %d is making an end-entity", j)
		err = tx.InsertEE("http://example.com/TestConcurrentEndEntityOperations",
			label, signerID)
		if err != nil {
			t.Fatalf("failed to insert end-entity into db: %v", err)
		}
	releaseLock:
		err = tx.End()
		if err != nil {
			t.Fatalf("failed to end end-entity db operations: %v", err)
		}
	case nil:
		t.Logf("TestConcurrentEndEntityOperations: routine %d is returning end-entity %q", j, label)
	default:
		t.Fatal(err)
	}
	return label
}

// simplified test types
type signerConfig struct {
	Signers        []signer        `json:"signers"`
	Authorizations []authorization `json:"authorizations"`
}

type authorization struct {
	ID      string   `json:"id"`
	Key     string   `json:"key"`
	Signers []string `json:"signers"`
}

type signer struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	Secret string `json:"secret,omitempty"`
	Foo    string `json:"foo,omitempty"`
}

func TestSignerConfigLoad(t *testing.T) {
	host := GetTestDBHost()
	db, err := Connect(Config{
		Name:                "autograph",
		User:                "myautographdbuser",
		Password:            "myautographdbpassword",
		Host:                host + ":5432",
		MonitorPollInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`delete from auth_signers;
			delete from signer;
			delete from auth;`)

	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`insert into auth(id, key)
		values('test1', 'abcdef0123456789'),
		('test2', 'abcdef0123456789');

		insert into signer(id, type, mode, secret, public)
		values('test1-1', 'type1', 'mode1', 'path/to/secret/test1-1', '{ "foo": "bar1" }'),
		('test1-2', 'type1', 'mode2', 'path/to/secret/test1-2', '{ "foo": "bar2" }'),
		('test1-3', 'type1', 'mode3', 'path/to/secret/test1-3', '{ "foo": "bar3" }'),
		('test2-1', 'type2', 'mode1', 'path/to/secret/test2-1', '{ "foo": "bar4" }'),
		('test2-2', 'type2', 'mode2', 'path/to/secret/test2-2', '{ "foo": "bar5" }'),
		('test-shared', 'type3', 'mode1', 'path/to/secret/test-shared', '{ "id": "bad-id", "foo": "bar6" }');

		insert into auth_signers(auth, signer)
		values('test1', 'test1-1'),
		('test1', 'test1-2'),
		('test1', 'test1-3'),
		('test1', 'test-shared'),
		('test2', 'test2-1'),
		('test2', 'test2-2'),
		('test2', 'test-shared');`)

	if err != nil {
		t.Fatal(err)
	}

	str, err := db.GetSignerConfig()
	if err != nil {
		t.Fatal(err)
	}

	var conf signerConfig
	err = json.Unmarshal([]byte(str), &conf)
	if err != nil {
		t.Fatal(err)
	}

	if len(conf.Authorizations) != 2 {
		t.Fatal("Should have 2 authorizations")
	}

	if len(conf.Authorizations[0].Signers)+len(conf.Authorizations[1].Signers) != 7 {
		t.Fatal("Should have 7 auth_signers")
	}

	if len(conf.Signers) != 6 {
		t.Fatal("Should have 6 signers")
	}

	for _, s := range conf.Signers {
		if s.ID == "bad-id" {
			t.Fatal("The signer id public property should have been overwritten by the record's id")
		}
	}

	t.Log("successfully read signer config from database")
}
