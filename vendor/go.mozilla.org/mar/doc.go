/*
Package mar implements support for the Mozilla ARchive format used by
the Application Update Service of Firefox.

The MAR format is specified at https://wiki.mozilla.org/Software_Update:MAR

This package is primarily used to sign MARs by first parsing them via the
Unmarshal function, then signing them with either RSA or ECDSA keys.

	// read a MAR file from disk
	input, _ := ioutil.ReadFile("/path/to/firefox.mar")
	// parse it
	_ = mar.Unmarshal(input, &file)
	// prepare a signature using a given RSA key
	file.PrepareSignature(rsaKey, rsaKey.Public())
	// sign
	_ = file.FinalizeSignatures()
	// write out the signed mar file
	output, _ := file.Marshal()
	ioutil.WriteFile("/path/to/signed_firefox.mar", output, 0644)

It can also be used to create new MARs and manipulate existing ones.

	// create a new MAR
	marFile := mar.New()
	// Add data to the content section
	marFile.AddContent([]byte("cariboumaurice"), "/foo/bar", 640)
	// Add product information to the additional section
	m.AddProductInfo("caribou maurice v1.2")
	// Add random data to the additional section
	m.AddAdditionalSection([]byte("foo bar baz"), uint32(1664))

The MAR data structure exposes all internal fields, including offsets,
sizes, etc. Those fields can be manipulated directly, but are ignored
and recomputed when marshalling.

The parser is fairly secure and will refuse to parse files that have
duplicate content or try to reference the same data chunk multiple
times. Doing so requires keeping track of previously parsed sections
of a MAR, which induces a significant memory cost. Be mindful of allocated
memory if you're going to parse a lot of very large MAR before the
garbage collector has a chance to reclaim memory from previously
parsed files.

Various limits are enforced, take a look at errors.go for the details.
*/
package mar
