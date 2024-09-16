// This code requires a configuration file to initialize the crypto11
// library. Use the following config in a file named "crypto11.config"
//
//	{
//	"Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//	"TokenLabel": "cavium",
//	"Pin" : "$CRYPTO_USER:$PASSWORD"
//	}
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/mozilla-services/autograph/crypto11"
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

	for keySize := 2048; keySize <= 4096; keySize += 256 {
		keyName := []byte(fmt.Sprintf("rsa%d-%d", keySize, time.Now().Unix()))
		fmt.Printf("making %q: ", keyName)
		rsakey, err := crypto11.GenerateRSAKeyPairOnSlot(slots[0], keyName, keyName, keySize)
		if err != nil {
			fmt.Printf("failed with %v\n", err)
		} else {
			fmt.Printf("%+v\n", rsakey)
		}
	}
}
