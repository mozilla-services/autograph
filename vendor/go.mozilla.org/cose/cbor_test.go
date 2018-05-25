package cose

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	codec "github.com/ugorji/go/codec"
	"reflect"
	"testing"
)

// Tests for encoding and decoding go-cose objects to and from CBOR

type CBORTestCase struct {
	name  string
	obj   interface{}
	bytes []byte
}

var CBORTestCases = []CBORTestCase{
	// golang data structures
	{
		"empty bstr",
		[]byte(""),
		[]byte("\x40"), // bytes(0) i.e. ""
	},
	{
		"generic interface map",
		map[interface{}]interface{}{1: -7},
		[]byte("\xA1\x01\x26"),
	},

	// SignMessage Headers
	{
		"sign message with empty headers",
		SignMessage{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{},
				Unprotected: map[interface{}]interface{}{},
			},
			Payload:    nil,
			Signatures: nil,
		},
		// D8 62     # tag(98) COSE SignMessage tag
		//    84     # array(4)
		//       40  # bytes(0) empty protected headers
		//           # ""
		//       A0  # map(0) empty unprotectd headers
		//       F6  # primitive(22) nil / null payload
		//       80  # array(0) no signatures
		[]byte("\xd8\x62\x84\x40\xa0\xf6\x80"),
	},
	{
		"sign message with alg in protected header",
		SignMessage{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{"alg": "ES256"},
				Unprotected: map[interface{}]interface{}{},
			},
			Payload:    nil,
			Signatures: nil,
		},
		// D8 62           # tag(98) COSE SignMessage tag
		//    84           # array(4)
		//       43        # bytes(3) bstr protected header
		//          A10126 # "\xA1\x01&"
		//       A0        # map(0) empty unprotected headers
		//       F6        # primitive(22) nil / null payload
		//       80        # array(0) no signatures
		//
		// where bstr h'A10126' is:
		//     A1   # map(1)
		//       01 # unsigned(1) common header ID for alg
		//       26 # negative(7) ES256 alg ID
		[]byte("\xd8\x62\x84\x43\xa1\x01\x26\xa0\xf6\x80"),
	},
	{
		"sign message with alg in unprotected header",
		SignMessage{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{},
				Unprotected: map[interface{}]interface{}{"alg": "ES256"},
			},
			Payload:    nil,
			Signatures: nil,
		},
		// D8 62        # tag(98) COSE SignMessage tag
		//    84        # array(4)
		//       40     # bytes(0) empty protected headers
		//              # ""
		//       A1     # map(1) unprotected headers
		//          01  # unsigned(1) common header ID for alg
		//          26  # negative(7) ES256 alg ID
		//       F6     # primitive(22) nil / null payload
		//       80     # array(0) no signatures
		[]byte("\xd8\x62\x84\x40\xa1\x01\x26\xf6\x80"),
	},
}

func MarshalsToExpectedBytes(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	bytes, err := Marshal(testCase.obj)
	assert.Nil(err)

	assert.Equal(testCase.bytes, bytes)
}

func UnmarshalsWithoutErr(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	_, err := Unmarshal(testCase.bytes)
	assert.Nil(err)
}

func RoundtripsToExpectedBytes(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	obj, err := Unmarshal(testCase.bytes)
	assert.Nil(err)

	bytes, err := Marshal(obj)
	assert.Nil(err)

	assert.Equal(testCase.bytes, bytes)
}

func TestCBOREncoding(t *testing.T) {
	for _, testCase := range CBORTestCases {
		t.Run(fmt.Sprintf("%s: MarshalsToExpectedBytes", testCase.name), func(t *testing.T) {
			MarshalsToExpectedBytes(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: UnmarshalsToExpectedInterface", testCase.name), func(t *testing.T) {
			UnmarshalsWithoutErr(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: RoundtripsToExpectedBytes", testCase.name), func(t *testing.T) {
			RoundtripsToExpectedBytes(t, testCase)
		})
	}
}

func TestCBORMarshalSignMessageWithNilHeadersErrors(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = nil
	msg.Headers = nil
	_, err := Marshal(msg)
	assert.Equal("cbor encode error: SignMessage has nil Headers", err.Error())
}

func TestCBORMarshalDuplicateKeysErrs(t *testing.T) {
	assert := assert.New(t)

	// NB: golang does not allow duplicate keys in a map literal
	// so we don't test Marshalling duplicate entries both in
	// Protected or Unprotected

	// uncompressed one in each
	msg := NewSignMessage()
	msg.Payload = nil
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": "ES256",
		},
		Unprotected: map[interface{}]interface{}{
			"alg": "PS256",
		},
	}
	_, err := Marshal(msg)
	assert.Equal(errors.New("cbor encode error: Duplicate header 1 found"), err)

	// compressed one in each
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			1: -7,
		},
		Unprotected: map[interface{}]interface{}{
			1: -37,
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor encode error: Duplicate header 1 found"), err)

	// compressed and uncompressed both in Protected
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": "ES256",
			1: -37,
		},
		Unprotected: map[interface{}]interface{}{
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor encode error: Duplicate compressed and uncompressed common header 1 found in headers"), err)

	// compressed and uncompressed both in Unprotected
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
		},
		Unprotected: map[interface{}]interface{}{
			"alg": "ES256",
			1: -37,
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor encode error: Duplicate compressed and uncompressed common header 1 found in headers"), err)

	// compressed and uncompressed one in each
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": "ES256",
		},
		Unprotected: map[interface{}]interface{}{
			1: -37,
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor encode error: Duplicate header 1 found"), err)

	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			1: -37,
		},
		Unprotected: map[interface{}]interface{}{
			"alg": "ES256",
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor encode error: Duplicate header 1 found"), err)

	// duplicate headers in a SignMessage Signature
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{},
	}
	msg.AddSignature(&Signature{
		Headers: &Headers{
			Protected: map[interface{}]interface{}{
				1: -37,
			},
			Unprotected: map[interface{}]interface{}{
				"alg": "ES256",
			},
		},
		SignatureBytes: []byte(""),
	})
	_, err = Marshal(msg)
	assert.Equal("cbor encode error: Duplicate signature header 1 found", err.Error())
}

func TestCBORDecodeNilSignMessagePayload(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = nil

	// tag(98) + array(4) [ bytes(0), map(0), nil/null, array(0) ]
	b := HexToBytesOrDie("D862" + "84" + "40" + "A0" + "F6" + "80" )

	result, err := Unmarshal(b)
	assert.Nil(err)
	assert.Equal(result, msg)

	bytes, err := Marshal(result)
	assert.Nil(err)
	assert.Equal(bytes, b)
}

func TestCBOREncodingErrsOnUnexpectedType(t *testing.T) {
	assert := assert.New(t)

	type Flub struct {
		foo string
	}
	obj := Flub{
		foo: "not a SignMessage",
	}

	h := GetCOSEHandle()
	var cExt Ext
	h.SetInterfaceExt(reflect.TypeOf(obj), SignMessageCBORTag, cExt)

	var b []byte
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, h)

	err := enc.Encode(obj)
	assert.Equal(errors.New("cbor encode error: unsupported format expecting to encode SignMessage; got *cose.Flub"), err)
}

func TestCBORDecodingDuplicateKeys(t *testing.T) {
	assert := assert.New(t)

	type DecodeTestCase struct {
		bytes        []byte
		result       SignMessage
	}
	var cases = []DecodeTestCase{
		{
			// duplicate compressed key in protected
			// tag(98) + array(4) [ bytes(5), map(0), bytes(0), array(0) ]
			//
			// where our bytes(5) is A201260128 or
			// A2    # map(2)
			//    01 # unsigned(1)
			//    26 # negative(6)
			//    01 # unsigned(1)
			//    29 # negative(10)
			//
			// and decodes to map[1:-10] so last/rightmost value wins
			HexToBytesOrDie("D862" + "84" + "45A201260129" + "A0" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected:   map[interface{}]interface{}{1: -10},
					Unprotected: map[interface{}]interface{}{},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
		{
			// duplicate compressed key in unprotected
			// tag(98) + array(4) [ bytes(0), map(2), bytes(0), array(0) ]
			//
			// where our map(2) is
			//    01 # unsigned(1)
			//    26 # negative(6)
			//    01 # unsigned(1)
			//    29 # negative(10)
			//
			// and decodes to map[1:-10] so last/rightmost value wins
			HexToBytesOrDie("D862" + "84" + "40" + "A201260129" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected:   map[interface{}]interface{}{},
					Unprotected: map[interface{}]interface{}{1: -10},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
		{
			// duplicate uncompressed key in protected
			// tag(98) + array(4) [ bytes(21), map(0), bytes(0), array(0) ]
			//
			// see next test for what bytes(21) represents
			HexToBytesOrDie("D862" + "84" + "55" + "A2" + "63" + "616C67" + "65" + "4553323536" + "63" + "616C67" + "65" + "5053323536" + "A0" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected: map[interface{}]interface{}{
						1: -37, // decoding compresses to check for duplicate keys
					},
					Unprotected: map[interface{}]interface{}{},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
		{
			// duplicate uncompressed key in unprotected
			// tag(98) + array(4) [ bytes(0), map(2), bytes(0), array(0) ]
			//
			// where our map(2) is
			//
			// A2               # map(2)
			//    63            # text(3)
			//       616C67     # "alg"
			//    65            # text(5)
			//       4553323536 # "ES256"
			//    63            # text(3)
			//       616C67     # "alg"
			//    65            # text(5)
			//       5053323536 # "PS256"
			//
			HexToBytesOrDie("D862" + "84" + "40" + "A2" + "63" + "616C67" + "65" + "4553323536" + "63" + "616C67" + "65" + "5053323536" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected: map[interface{}]interface{}{},
					Unprotected: map[interface{}]interface{}{
						1: -37, // decoding compresses to check for duplicate keys
					},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
	}

	for _, testCase := range cases {
		result, err := Unmarshal(testCase.bytes)
		assert.Nil(err)
		assert.Equal(testCase.result, result)
	}
}

func TestCBORDecodingErrors(t *testing.T) {
	assert := assert.New(t)

	type DecodeErrorTestCase struct {
		bytes        []byte
		errorMessage string
	}
	var cases = []DecodeErrorTestCase{
		{
			HexToBytesOrDie("D862" + "60"), // tag(98) + text(0)
			"cbor decode error [pos 3]: unsupported format expecting to decode from []interface{}; got string",
		},
		{
			HexToBytesOrDie("D862" + "80"), // tag(98) + array(0)
			"cbor decode error [pos 3]: can only decode SignMessage with 4 fields; got 0",
		},
		{
			// tag(98) + array(4) [ 4 * text(0) ]
			HexToBytesOrDie("D862" + "84" + "60" + "60" + "60" + "60"),
			"cbor decode error [pos 7]: error decoding header bytes; got error casting protected header bytes; got string",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), 2 * text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "60" + "60"),
			"cbor decode error [pos 7]: error decoding msg payload decode from interface{} to []byte or nil; got type string",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "60"),
			"cbor decode error [pos 7]: error decoding sigs; got string",
		},
		{
			// wrong # of protected header bytes
			// tag(98) + array(4) [ bytes(2) (but actually 1), map(0), bytes(0), text(0) ]
			HexToBytesOrDie("D862" + "84" + "4263" + "A0" + "40" + "60"),
			"EOF",
		},
		{
			// duplicate compressed key in protected and unprotected
			// tag(98) + array(4) [ bytes(3), map(2), bytes(0), array(0) ]
			// bytes(3) is protected {2: -7}
			// map(1) is {2: -5}
			HexToBytesOrDie("D862" + "84" + "43A10226" + "A10224" + "40" + "80"),
			"cbor decode error [pos 12]: error decoding header bytes; got Duplicate header 2 found",
		},
		{
			// duplicate uncompressed key in protected and unprotected
			// tag(98) + array(4) [ bytes(11), map(1), bytes(0), array(0) ]
			// bytes(11) is protected {"alg": "ES256"}
			// map(1) is unprotected {"alg": "ES256"}
			HexToBytesOrDie("D862" + "84" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40" + "80"),
			"cbor decode error [pos 28]: error decoding header bytes; got Duplicate header 1 found",
		},
		{
			// duplicate key compressed in protected and uncompressed in unprotected
			// tag(98) + array(4) [ bytes(3), map(1), bytes(0), array(0) ]
			// bytes(3) is protected {1: -7}
			// map(1) is unprotected {"alg": "PS256"}
			HexToBytesOrDie("D862" + "84" + "43" + "A10126" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40" + "80"),
			"cbor decode error [pos 20]: error decoding header bytes; got Duplicate header 1 found",
		},
		{
			// duplicate key uncompressed in protected and compressed in unprotected
			// tag(98) + array(4) [ bytes(11), map(1), bytes(0), array(0) ]
			// bytes(11) is protected {"alg": "ES256"}
			// map(1) is unprotected {1: -7}
			HexToBytesOrDie("D862" + "84" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A10126" + "40" + "80"),
			"cbor decode error [pos 20]: error decoding header bytes; got Duplicate header 1 found",
		},
	}

	for _, testCase := range cases {
		result, err := Unmarshal(testCase.bytes)
		assert.Nil(result)
		assert.Equal(errors.New(testCase.errorMessage), err)
	}

	// test decoding into the wrong dest type
	type Flub struct {
		foo string
	}
	obj := Flub{
		foo: "not a SignMessage",
	}

	h := GetCOSEHandle()
	var cExt Ext
	h.SetInterfaceExt(reflect.TypeOf(obj), SignMessageCBORTag, cExt)

	// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(0) ]
	var dec *codec.Decoder = codec.NewDecoderBytes(HexToBytesOrDie("D862"+"84"+"40"+"A0"+"40"+"80"), h)

	err := dec.Decode(&obj)
	assert.Equal(errors.New("cbor decode error [pos 7]: unsupported format expecting to decode into *SignMessage; got *cose.Flub"), err)
}
