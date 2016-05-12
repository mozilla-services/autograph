package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
)

func main() {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	w, x, y, z := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	w.SetBytes(b[:8])
	x.SetBytes(b[8:16])
	y.SetBytes(b[16:24])
	z.SetBytes(b[24:32])
	fmt.Printf("256bits random token: %s%s%s%s\n",
		strconv.FormatUint(w.Uint64(), 36),
		strconv.FormatUint(x.Uint64(), 36),
		strconv.FormatUint(y.Uint64(), 36),
		strconv.FormatUint(z.Uint64(), 36))
}
