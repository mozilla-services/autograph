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
		_, _, rng, _, err := testcase.cfg.GetKeysAndRand()
		if err != nil {
			t.Fatalf("testcase %d failed to load signer configuration: %v", i, err)
		}
		randomData := make([]byte, 512)
		_, err = rng.Read(randomData)
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

var PASSINGTESTCASES = []struct {
	cfg Configuration
}{
	{cfg: Configuration{
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
-----END EC PRIVATE KEY-----`,
	}},
	{cfg: Configuration{
		PrivateKey: `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDYU0DX8fqlyaJqha6D0DvHAtde8o3xIxXYX8ONwVbUIJMur+42
rsXZk8vQkeSzQ9evIAlara5X9aSvCo0O4Lg7VzHjRd5Ip2RwWAknJY942XCBF+CO
M9NTwjQRlBjNrRK9Qm3gRHLkCsw5mqDkzXXPkKXw5jeiveAsQIES40YgIwIDAQAB
AoGAESQfqjzRWJuuk/Q9zNIOOom+GRbtKmNWUsvbyfq875gZMYTdQlX89W2ho8g7
r/y7NXQ7aYUDoJKlVv1mCfzCfEPsl+AppNzRWf7Dsvgv4OHLCMP6pzliSWz+Teh3
eybe17v8OtmrWWRZpf+mBdIBZ1AUFh9ET9hHsil5I7s2VjkCQQD049sKsFdltnqJ
nfkFhyxWomNhmY4f37iUOl562gcP71Dqg+IeB7mTaqxc2KwErZYPb0H+ov8NxNLJ
GPva6FB1AkEA4iOlgES3aIPeoYYoqKRrYxx4kOO0s2cRxlEbt+nbDgdxIjsxeS29
Fz/p9GCsutHrpAwIBDNrgmG5V0yfE06bNwJBAI7hBmLFIijQ/8udJLaJ+F+PnUZL
jjWglRO+vnMVFDvC2EYLrnjw7uBIw8nkDPEpyjy1IB8OQJtq88Sq0/8TviUCQH0s
Jgvd/XeIps7Zp9/RQu/Vbpcks30qbBhOBP3EIFCfpevAwB3HR4d7BVETwgiW8cwY
LMfGfpfo5+J+sv7I3/kCQEvkxSGguHckNzqV7nZgwskbFfvTVLqMaPy9EVfu2od+
ZkJ9hRz+l4ZVOsgNPHXPEi0AXWnDV6zrRQBpDYyiGhY=
-----END RSA PRIVATE KEY-----`,
	}},
}
