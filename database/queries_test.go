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
		Name:     "autograph",
		User:     "myautographdbuser",
		Password: "myautographdbpassword",
		Host:     "127.0.0.1:5432",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	concurrency := 100
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

	tx, err := db.BeginEndEntityOperations()
	if err != nil {
		t.Fatalf("failed to begin end-entity db operations: %v", err)
	}
	label, _, err := tx.GetLabelOfLatestEE(signerID, 15*time.Second)
	switch err {
	case ErrNoSuitableEEFound:
		// make a new EE
		label = fmt.Sprintf("%d", time.Now().UnixNano())
		t.Logf("TestConcurrentEndEntityOperations: routine %d is making an end-entity", j)
		err = tx.InsertEE("http://example.com/TestConcurrentEndEntityOperations",
			label, signerID, uint(j))
		if err != nil {
			t.Fatalf("failed to insert end-entity into db: %v", err)
		}
	case nil:
		t.Logf("TestConcurrentEndEntityOperations: routine %d is returning end-entity %q", j, label)
	default:
		t.Fatal(err)
	}
	err = tx.End()
	if err != nil {
		t.Fatalf("failed to end end-entity db operations: %v", err)
	}
	return label
}
