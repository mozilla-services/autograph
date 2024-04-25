// This code requires a configuration file to initialize the crypto11
// library. Use the following config in a file named crypto11.config:
//
//	{
//	"Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//	"TokenLabel": "cavium",
//	"Pin" : "$CRYPTO_USER:$PASSWORD"
//	}
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ThalesIgnite/crypto11"
)

var wg sync.WaitGroup

func main() {
	p11Ctx, err := crypto11.ConfigureFromFile("crypto11.config")
	if err != nil {
		log.Fatal(err)
	}
	slots, err := p11Ctx.GetSlotList(true)
	if err != nil {
		log.Fatalf("Failed to list PKCS#11 Slots: %s", err.Error())
	}
	if len(slots) < 1 {
		log.Fatal("No slot found")
	}

	// try to make 3 keys with the same label at the same time
	wg.Add(3)
	keyName := fmt.Sprintf("testdup%d", time.Now().Unix())
	i := 0
	go waitAndMakeKey(slots, i, keyName)
	i++
	go waitAndMakeKey(slots, i, keyName)
	i++
	go waitAndMakeKey(slots, i, keyName)

	wg.Wait()

	// now try to make a key with the same label after the routine are done
	ecdsakey, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], []byte(keyName), []byte(keyName), elliptic.P384())
	if err != nil {
		log.Printf("failed to make key %s in main thread: %v", keyName, i, err)
	} else {
		log.Printf("main thread made ECDSA Key named %q: %+v %+v", i, keyName, ecdsakey, ecdsakey.Public().(*ecdsa.PublicKey).Params())
	}
}

func waitAndMakeKey(slots []uint, i int, keyName string) {
	defer wg.Done()
	log.Printf("starting routine %d", i)
	nextTime := time.Now().Truncate(time.Minute)
	nextTime = nextTime.Add(time.Minute)
	time.Sleep(time.Until(nextTime))
	ecdsakey, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], []byte(keyName), []byte(keyName), elliptic.P384())
	if err != nil {
		log.Printf("failed to make key %s in routine %d: %v", keyName, i, err)
	} else {
		log.Printf("routine %d made ECDSA Key named %q: %+v %+v", i, keyName, ecdsakey, ecdsakey.Public().(*ecdsa.PublicKey).Params())
	}
}
