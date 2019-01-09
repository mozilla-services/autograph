// This code requires a configuration file to initialize the crypto11
// library. Use the following config in a file named "crypto11.config"
//      {
//      "Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//      "TokenLabel": "cavium",
//      "Pin" : "$CRYPTO_USER:$PASSWORD"
//      }
package main

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"time"

	"github.com/ThalesIgnite/crypto11"
)

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
	suffix := fmt.Sprintf("%d", time.Now().Unix())

	keyName := []byte("testrsa2048-" + suffix)
	fmt.Printf("making %q: ", keyName)
	rsakey, err := crypto11.GenerateRSAKeyPairOnSlot(slots[0], keyName, keyName, 2048)
	if err != nil {
		fmt.Printf("failed with %v\n", err)
	} else {
		fmt.Printf("%+v\n", rsakey)
	}

	keyName = []byte("testrsa4096-" + suffix)
	fmt.Printf("making %q: ", keyName)
	rsakey2, err := crypto11.GenerateRSAKeyPairOnSlot(slots[0], keyName, keyName, 4096)
	if err != nil {
		fmt.Printf("failed with %v\n", err)
	} else {
		fmt.Printf("%+v\n", rsakey2)
	}

	keyName = []byte("testecdsap256-" + suffix)
	fmt.Printf("making %q: ", keyName)
	ecdsakey, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], keyName, keyName, elliptic.P256())
	if err != nil {
		fmt.Printf("failed with %v\n", err)
	} else {
		fmt.Printf("%+v\n", ecdsakey)
	}

	keyName = []byte("testecdsap384-" + suffix)
	fmt.Printf("making %q: ", keyName)
	p384key, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], keyName, keyName, elliptic.P384())
	if err != nil {
		fmt.Printf("failed with %v\n", err)
	} else {
		fmt.Printf("%+v\n", p384key)
	}
}
