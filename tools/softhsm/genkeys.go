// This code requires a configuration file to initialize the crypto11
// library. Use the following config in crypto11.config:
//      {
//      "Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//      "TokenLabel": "cavium",
//      "Pin" : "$CRYPTO_USER:$PASSWORD"
//      }
// then invoke the program with:
// !CKNFAST_DEBUG=2 CRYPTO11_CONFIG_PATH=crypto11.config go run crypto11_genrsa.go
package main

import (
	"crypto/elliptic"
	"fmt"
	"log"

	"github.com/ThalesIgnite/crypto11"
)

func main() {
	p11Ctx, err := crypto11.Configure(&crypto11.PKCS11Config{
		Path:       "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "test",
		Pin:        "0000",
	})
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
	rsakey, err := crypto11.GenerateRSAKeyPairOnSlot(slots[0], []byte("testrsa2048"), []byte("testrsa2048"), 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("RSA Key: %+v\n", rsakey)

	rsakey2, err := crypto11.GenerateRSAKeyPairOnSlot(slots[0], []byte("testrsa2048"), []byte("testrsa4096"), 4096)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("RSA 4096 Key: %+v\n", rsakey2)

	ecdsakey, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], []byte("testecdsap384"), []byte("testecdsap384"), elliptic.P384())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ECDSA Key: %+v\n", ecdsakey)

	p384key, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], []byte("testcsp384"), []byte("testcsp384"), elliptic.P384())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("P384 Key: %+v\n", p384key)
}
