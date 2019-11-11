package database

import (
	"reflect"
	"testing"
	"time"

	"go.mozilla.org/autograph/formats"
)

func createAndCheckDB(t *testing.T, config Config) (handler *Handler) {
	var (
		one uint
		err error
	)
	handler, err = Connect(config)
	if err != nil {
		t.Fatal(err)
	}
	err = handler.QueryRow("SELECT 1").Scan(&one)
	if err != nil || one != 1 {
		t.Fatal("Database connection failed:", err)
	}
	return
}

func TestInsertAndGetAuths(t *testing.T) {
	adminDB := createAndCheckDB(t, Config{
		Name:                "autograph",
		User:                "myautographdbauthadmin",
		Password:            "myautographdbauthadminpassword",
		Host:                "127.0.0.1:5432",
		MonitorPollInterval: 10 * time.Second,
	})
	defer adminDB.Close()
	userDB := createAndCheckDB(t, Config{
		Name:                "autograph",
		User:                "myautographdbuser",
		Password:            "myautographdbpassword",
		Host:                "127.0.0.1:5432",
		MonitorPollInterval: 10 * time.Second,
	})
	defer userDB.Close()

	var (
		count int
		err   error
		auth  = formats.Authorization{
			ID:                    "test-hawk-id",
			Key:                   "cdbc735007c1c1ed5f3f1d97c0a71b5260ae1e6d6d50ef1e561d0b9c6342073c",
			HawkTimestampValidity: time.Minute * 5,
			Signers:               []string{"test-signer-1", "test-signer-2"},
		}
		badAuth = formats.Authorization{
			ID:                    "-invalid-hawk-id",
			Key:                   "cdbc735007c1c1ed5f3f1d97c0a71b5260ae1e6d6d50ef1e561d0b9c6342073c",
			HawkTimestampValidity: time.Minute * 5,
			Signers:               []string{"test-signer-1", "test-signer-2"},
		}
	)
	err = adminDB.InsertAuthorization(badAuth)
	if err == nil {
		t.Fatal("did not fail to insert bad authorization")
	}

	err = adminDB.InsertAuthorization(auth)
	if err != nil {
		t.Fatal("failed to insert authorization:", err)
	}
	err = adminDB.QueryRow("SELECT COUNT(1) FROM authorizations").Scan(&count)
	if err != nil {
		t.Fatal("failed to select auths:", err)
	}
	if count != len(auth.Signers) {
		t.Fatalf("got unexpected # of authorization rows wanted %d got %d", len(auth.Signers), count)
	}

	auths, err := userDB.GetAuthorizations()
	if err != nil {
		t.Fatal("failed to get authorization:", err)
	}
	if len(auths) < 1 {
		t.Fatalf("got unexpected # of auths wanted %d got %d", 1, len(auths))
	}
	if !reflect.DeepEqual(auths[0], auth) {
		t.Fatalf("got different auth then saved got %+v but wanted %+v", auths[0], auth)
	}

	err = userDB.InsertAuthorization(auth)
	if err == nil {
		t.Fatal("autograph db user inserted authorization when it shouldn't have been able to")
	}
}
