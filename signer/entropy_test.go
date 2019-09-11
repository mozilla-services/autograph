package signer

import (
	"bytes"
	"math"
	"testing"
)

// returns the shannon entropy of a byte string
func shannonEntropy(data []byte) (entropy float64) {
	if len(data) == 0 {
		return 0
	}
	for i := 0; i < 256; i++ {
		var curByte []byte
		curByte = append(curByte, byte(i))
		px := float64(bytes.Count(data, curByte)) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}
	return entropy
}

func TestRng(t *testing.T) {
	for i, testcase := range PASSINGTESTCASES {
		rng := testcase.cfg.GetRand()
		randomData := make([]byte, 512)
		_, err := rng.Read(randomData)
		if err != nil {
			t.Fatalf("testcase %d failed to read from rng: %v", i, err)
		}
		entropy := shannonEntropy(randomData)
		t.Logf("testcase %d returned entropy %f", i, entropy)
		if entropy < 7.0 {
			t.Fatalf("testcase %d got low entropy from rng: received %f, expected at least 7", i, entropy)
		}
	}
}
