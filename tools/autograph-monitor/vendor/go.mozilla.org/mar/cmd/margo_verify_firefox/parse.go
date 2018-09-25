package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"go.mozilla.org/mar"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <file> [json]\nParse and Verify the signature of a Firefox MAR.\nIf json is set as 2nd arg, dump the MAR as JSON too.\n", os.Args[0])
		os.Exit(1)
	}
	var file mar.File
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("Error while opening fd", err)
	}
	err = mar.Unmarshal(input, &file)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 2 && os.Args[2] == "json" {
		o, err := json.MarshalIndent(file, "", "    ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", o)
	} else {
		fmt.Printf("%s\tsize=%d bytes\tsignatures=%d\tcontent=%d entries\tproduct=%q\trevision=%d\n",
			file.MarID, file.Size,
			file.SignaturesHeader.NumSignatures, len(file.Index),
			file.ProductInformation, file.Revision)
	}
	if file.Revision < 2012 {
		fmt.Printf("MAR format precedes 2012 and does not support signatures.")
		os.Exit(0)
	}
	validKeys, isSigned, err := file.VerifyWithFirefoxKeys()
	if err != nil {
		log.Fatal(err)
	}
	if !isSigned {
		fmt.Println("signature: no valid signature found")
	} else {
		fmt.Printf("signature: OK, valid signature from %s\n", strings.Join(validKeys, ","))
	}
}
