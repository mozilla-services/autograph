package cose

import (
	"fmt"
	"github.com/pkg/errors"
)

// Headers represents "two buckets of information that are not
// considered to be part of the payload itself, but are used for
// holding information about content, algorithms, keys, or evaluation
// hints for the processing of the layer."
//
// https://tools.ietf.org/html/rfc8152#section-3
//
// It is represented by CDDL fragments:
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
type Headers struct {
	Protected   map[interface{}]interface{}
	Unprotected map[interface{}]interface{}
}

// EncodeUnprotected returns compressed unprotected headers
func (h *Headers) EncodeUnprotected() (encoded map[interface{}]interface{}) {
	return CompressHeaders(h.Unprotected)
}

// EncodeProtected compresses and Marshals protected headers to bytes
// to encode as a CBOR bstr
func (h *Headers) EncodeProtected() (bstr []byte) {
	if h == nil {
		panic("Cannot encode nil Headers")
	}

	if h.Protected == nil || len(h.Protected) < 1 {
		return []byte("")
	}

	encoded, err := Marshal(CompressHeaders(h.Protected))
	if err != nil {
		panic(fmt.Sprintf("Marshal error of protected headers %s", err))
	}
	return encoded
}

// DecodeProtected Unmarshals and sets Headers.protected from an interface{}
func (h *Headers) DecodeProtected(o interface{}) (err error) {
	if h == nil {
		return errors.New("error decoding protected headers on nil headers")
	}

	b, ok := o.([]byte)
	if !ok {
		return errors.Errorf("error casting protected header bytes; got %T", o)
	}
	if len(b) <= 0 {
		return nil
	}

	protected, err := Unmarshal(b)
	if err != nil {
		return errors.Errorf("error CBOR decoding protected header bytes; got %T", protected)
	}
	protectedMap, ok := protected.(map[interface{}]interface{})
	if !ok {
		return errors.Errorf("error casting protected to map; got %T", protected)
	}
	h.Protected = protectedMap
	return nil
}

// DecodeUnprotected Unmarshals and sets Headers.unprotected from an interface{}
func (h *Headers) DecodeUnprotected(o interface{}) (err error) {
	msgHeadersUnprotected, ok := o.(map[interface{}]interface{})
	if !ok {
		return errors.Errorf("error decoding unprotected header as map[interface {}]interface {}; got %T", o)
	}
	h.Unprotected = msgHeadersUnprotected
	return nil
}

// Decode loads a two element interface{} slice into Headers.protected
// and unprotected respectively
func (h *Headers) Decode(o []interface{}) (err error) {
	if len(o) != 2 {
		return errors.Errorf("can only decode headers from 2-item array; got %d", len(o))
	}
	err = h.DecodeProtected(o[0])
	if err != nil {
		return err
	}
	err = h.DecodeUnprotected(o[1])
	if err != nil {
		return err
	}
	dup := FindDuplicateHeader(h)
	if dup != nil {
		return errors.Errorf("Duplicate header %+v found", dup)
	}
	return nil
}

// GetCommonHeaderTag returns the CBOR tag for the map label
//
// using Common COSE Headers Parameters Table 2
// https://tools.ietf.org/html/rfc8152#section-3.1
func GetCommonHeaderTag(label string) (tag int, err error) {
	switch label {
	case "alg":
		return 1, nil
	case "crit":
		return 2, nil
	case "content type":
		return 3, nil
	case "kid":
		return 4, nil
	case "IV":
		return 5, nil
	case "Partial IV":
		return 6, nil
	case "counter signature":
		return 7, nil
	default:
		return 0, ErrMissingCOSETagForLabel
	}
}

// GetCommonHeaderTagOrPanic returns the CBOR label for a string. Is
// the inverse of GetCommonHeaderLabel.
func GetCommonHeaderTagOrPanic(label string) (tag int) {
	tag, err := GetCommonHeaderTag(label)
	if err != nil {
		panic(fmt.Sprintf("Failed to find a tag for label %s", label))
	}
	return tag
}

// GetCommonHeaderLabel returns the CBOR label for the map tag.  Is
// the inverse of GetCommonHeaderTag.
func GetCommonHeaderLabel(tag int) (label string, err error) {
	switch tag {
	case 1:
		return "alg", nil
	case 2:
		return "crit", nil
	case 3:
		return "content type", nil
	case 4:
		return "kid", nil
	case 5:
		return "IV", nil
	case 6:
		return "Partial IV", nil
	case 7:
		return "counter signature", nil
	default:
		return "", ErrMissingCOSETagForTag
	}
}

// getAlgByName returns a Algorithm for an IANA name
func getAlgByName(name string) (alg *Algorithm, err error) {
	for _, alg := range algorithms {
		if alg.Name == name {
			return &alg, nil
		}
	}
	return nil, errors.Errorf("Algorithm named %s not found", name)
}

// getAlgByNameOrPanic returns a Algorithm for an IANA name and panics otherwise
func getAlgByNameOrPanic(name string) (alg *Algorithm) {
	alg, err := getAlgByName(name)
	if err != nil {
		panic(fmt.Sprintf("Unable to get algorithm named %s", name))
	}
	return alg
}

// getAlgByValue returns a Algorithm for an IANA value
func getAlgByValue(value int) (alg *Algorithm, err error) {
	for _, alg := range algorithms {
		if alg.Value == value {
			return &alg, nil
		}
	}
	return nil, errors.Errorf("Algorithm with value %v not found", value)
}

func compressHeader(k, v interface{}) (compressedK, compressedV interface{}) {
	var keyIsAlg = false

	compressedK = k
	compressedV = v

	switch key := k.(type) {
	case string:
		if key == "alg" {
			keyIsAlg = true
		}
		tag, err := GetCommonHeaderTag(key)
		if err == nil {
			compressedK = tag
		}
	case int64:
		compressedK = int(key)
	}

	switch val := v.(type) {
	case string:
		if keyIsAlg {
			alg, err := getAlgByName(val)
			if err == nil {
				compressedV = alg.Value
			}
		}
	case int64:
		compressedV = int(val)
	}
	return
}

func decompressHeader(k, v interface{}) (decompressedK, decompressedV interface{}) {
	var keyIsAlg = false

	decompressedK = k
	decompressedV = v

	switch key := k.(type) {
	case int:
		label, err := GetCommonHeaderLabel(key)
		if err == nil {
			decompressedK = label
		}
		if label == "alg" {
			keyIsAlg = true
		}
	}

	switch val := v.(type) {
	case int:
		if keyIsAlg {
			alg, err := getAlgByValue(val)
			if err == nil {
				decompressedV = alg.Name
			}
		}
	}
	return
}

// CompressHeaders replaces string tags with their int values and alg
// tags with their IANA int values.
//
// panics when a compressed header tag already exists (e.g. alg and 1)
// casts int64 keys to int to make looking up common header IDs easier
func CompressHeaders(headers map[interface{}]interface{}) (compressed map[interface{}]interface{}) {
	compressed = map[interface{}]interface{}{}
	for k, v := range headers {
		compressedK, compressedV := compressHeader(k, v)
		if _, ok := compressed[compressedK]; ok {
			panic(fmt.Sprintf("Duplicate compressed and uncompressed common header %v found in headers", compressedK))
		} else {
			compressed[compressedK] = compressedV
		}
	}
	return compressed
}

// DecompressHeaders replaces int values with string tags and alg int
// values with their IANA labels. Is the inverse of CompressHeaders.
func DecompressHeaders(headers map[interface{}]interface{}) (decompressed map[interface{}]interface{}) {
	decompressed = map[interface{}]interface{}{}

	for k, v := range headers {
		k, v = decompressHeader(k, v)
		decompressed[k] = v
	}

	return decompressed
}

// FindDuplicateHeader compresses the headers and returns the first
// duplicate header or nil for none found
func FindDuplicateHeader(headers *Headers) interface{} {
	if headers == nil {
		return nil
	}
	headers.Protected = CompressHeaders(headers.Protected)
	headers.Unprotected = CompressHeaders(headers.Unprotected)
	for k, _ := range headers.Protected {
		_, ok := headers.Unprotected[k]
		if ok {
			return k
		}
	}
	return nil
}

// getAlg returns the alg by label or int
// alg should only be in Protected headers so it does not check Unprotected headers
func getAlg(h *Headers) (alg *Algorithm, err error) {
	if h == nil {
		err = errors.New("Cannot getAlg on nil Headers")
		return
	}

	if tmp, ok := h.Protected["alg"]; ok {
		if algName, ok := tmp.(string); ok {
			alg, err = getAlgByName(algName)
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	} else if tmp, ok := h.Protected[int(1)]; ok {
		if algValue, ok := tmp.(int); ok {
			alg, err = getAlgByValue(algValue)
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	}
	return nil, ErrAlgNotFound
}
