package cose

import (
	"bytes"
	"fmt"
	codec "github.com/ugorji/go/codec"
	"reflect"
)

// SignMessageCBORTag is the CBOR tag for a COSE SignMessage
// from https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const SignMessageCBORTag = 98

var signMessagePrefix = []byte{
	// 0b110_11000 major type 6 (tag) with additional information
	// length 24 bits / 3 bytes (since tags are always uints)
	//
	// per https://tools.ietf.org/html/rfc7049#section-2.4
	'\xd8',

	// uint8_t with the tag value
	SignMessageCBORTag,

	// 0b100_00100 major type 4 (array) with additional
	// information 4 for a 4-item array representing a COSE_Sign
	// message
	'\x84',
}

// IsSignMessage checks whether the prefix is 0xd8 0x62 for a COSE
// SignMessage
func IsSignMessage(data []byte) bool {
	return bytes.HasPrefix(data, signMessagePrefix)
}

// GetCOSEHandle returns a codec.CborHandle with an extension
// registered for COSE SignMessage as CBOR tag 98
func GetCOSEHandle() (h *codec.CborHandle) {
	h = new(codec.CborHandle)
	h.IndefiniteLength = false // no streaming
	h.Canonical = true         // sort map keys
	h.SignedInteger = true

	var cExt Ext
	h.SetInterfaceExt(reflect.TypeOf(SignMessage{}), SignMessageCBORTag, cExt)
	return h
}

// Marshal returns the CBOR []byte encoding of param o
func Marshal(o interface{}) (b []byte, err error) {
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, GetCOSEHandle())

	err = enc.Encode(o)
	return b, err
}

// Unmarshal returns the CBOR decoding of a []byte into param o
func Unmarshal(b []byte) (o interface{}, err error) {
	var dec *codec.Decoder = codec.NewDecoderBytes(b, GetCOSEHandle())

	err = dec.Decode(&o)
	return o, err
}

// Ext is a codec.cbor extension to handle custom (de)serialization of
// types to/from another interface{} value
//
// https://godoc.org/github.com/ugorji/go/codec#InterfaceExt
type Ext struct{}

// ConvertExt converts a value into a simpler interface for easier
// encoding
func (x Ext) ConvertExt(v interface{}) interface{} {
	message, ok := v.(*SignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting to encode SignMessage; got %T", v))
	}
	if message.Headers == nil {
		panic("SignMessage has nil Headers")
	}
	dup := FindDuplicateHeader(message.Headers)
	if dup != nil {
		panic(fmt.Sprintf("Duplicate header %+v found", dup))
	}

	sigs := make([]interface{}, len(message.Signatures))
	for i, s := range message.Signatures {
		dup := FindDuplicateHeader(s.Headers)
		if dup != nil {
			panic(fmt.Sprintf("Duplicate signature header %+v found", dup))
		}

		sigs[i] = []interface{}{
			s.Headers.EncodeProtected(),
			s.Headers.EncodeUnprotected(),
			s.SignatureBytes,
		}
	}

	return []interface{}{
		message.Headers.EncodeProtected(),
		message.Headers.EncodeUnprotected(),
		[]byte(message.Payload),
		sigs,
	}
}

// UpdateExt updates a value from a simpler interface for easy
// decoding dest is always a pointer to a SignMessage
//
// Note: dest is always a pointer kind to the registered extension type.
//
// Unpacks a SignMessage described by CDDL fragments:
//
// COSE_Sign = [
//     Headers,
//     payload : bstr / nil,
//     signatures : [+ COSE_Signature]
// ]
//
// COSE_Signature =  [
//     Headers,
//     signature : bstr
// ]
//
// Headers = (
//     protected : empty_or_serialized_map,
//     unprotected : header_map
// )
//
// header_map = {
//     Generic_Headers,
//     * label => values
// }
//
// empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
//
// Generic_Headers = (
//        ? 1 => int / tstr,  ; algorithm identifier
//        ? 2 => [+label],    ; criticality
//        ? 3 => tstr / int,  ; content type
//        ? 4 => bstr,        ; key identifier
//        ? 5 => bstr,        ; IV
//        ? 6 => bstr,        ; Partial IV
//        ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
// )
//
// Note: the decoder will convert panics to errors
func (x Ext) UpdateExt(dest interface{}, v interface{}) {
	message, ok := dest.(*SignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting to decode into *SignMessage; got %T", dest))
	}

	var src, vok = v.([]interface{})
	if !vok {
		panic(fmt.Sprintf("unsupported format expecting to decode from []interface{}; got %T", v))
	}
	if len(src) != 4 {
		panic(fmt.Sprintf("can only decode SignMessage with 4 fields; got %d", len(src)))
	}

	var msgHeaders = &Headers{
		Protected:   map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{},
	}
	err := msgHeaders.Decode(src[0:2])
	if err != nil {
		panic(fmt.Sprintf("error decoding header bytes; got %s", err))
	}

	message.Headers = msgHeaders

	switch payload := src[2].(type) {
	case []byte:
		message.Payload = payload
	case nil:
		message.Payload = nil
	default:
		panic(fmt.Sprintf("error decoding msg payload decode from interface{} to []byte or nil; got type %T", src[2]))
	}

	var sigs, sok = src[3].([]interface{})
	if !sok {
		panic(fmt.Sprintf("error decoding sigs; got %T", src[3]))
	}
	for _, sig := range sigs {
		sigT := NewSignature()
		sigT.Decode(sig) // can panic
		message.AddSignature(sigT)
	}
}
