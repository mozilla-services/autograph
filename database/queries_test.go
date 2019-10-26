// +build !race

package database

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestConcurrentEndEntityOperations(t *testing.T) {
	db, err := Connect(Config{
		Name:                "autograph",
		User:                "myautographdbuser",
		Password:            "myautographdbpassword",
		Host:                "127.0.0.1:5432",
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
	labels := make(map[string]bool)
	for i := 0; i < concurrency; i++ {
		go func(j int) {
			label := waitAndMakeEE(j, db, &wg, t, signerID)
			labels[label] = true
		}(i)
	}
	wg.Wait()
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
	// sleep until the next 10s, then start
	nextTime := time.Now().Truncate(10 * time.Second)
	nextTime = nextTime.Add(10 * time.Second)
	time.Sleep(time.Until(nextTime))

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
			label, signerID, uint(j))
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
