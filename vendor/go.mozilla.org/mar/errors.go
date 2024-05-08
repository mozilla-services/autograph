package mar

import (
	"errors"
	"fmt"
)

var (
	limitMinFileSize uint64 = uint64(MarIDLen + OffsetToIndexLen + FileSizeLen + IndexHeaderLen + IndexEntryHeaderLen)

	// the maximum size we'll agree to parse is 500MB.
	// also set in Firefox at modules/libmar/src/mar_private.h#24-26
	//
	// People From The Future, if this isn't large enough for you, feel
	// free to increase it, and have some self reflection because 640k
	// oughta be enough for everybody!
	limitMaxFileSize uint64 = 524288000

	// filenames in the index shouldn't be longer than 1024 characters
	limitFileNameLength = 1024

	// an rsa signature on a 4096 bits key is 512 bytes, so by allowing 2k
	// we could go up to 16k bit keys, which seems unlikely
	// also set in Firefox at modules/libmar/src/mar_private.h#39-41
	limitMaxSignatureSize uint32 = 2048

	// additional data have a max size of 10MB
	limitMaxAdditionalDataSize uint32 = 10485760
)

var (
	errBadMarID                 = errors.New("mar ID must be MAR1")
	errOffsetTooSmall           = errors.New("offset to index is too small to be valid")
	errBadSigAlg                = errors.New("bad signature algorithm")
	errInputTooShort            = errors.New("refusing to read more bytes than present in input")
	errMalformedFileSize        = errors.New("the total file size does not match offset + index size")
	errTooSmall                 = errors.New("the total file is below the minimum allowed of 32 bytes")
	errTooBig                   = errors.New("the total file exceeds the maximum allowed of 500MB")
	errSignatureTooBig          = errors.New("signature exceeds maximum allowed of 2048 bytes")
	errSignatureUnknown         = errors.New("signature algorithm is unknown")
	errAdditionalDataTooBig     = errors.New("additional data exceeds maximum allowed of 10MB")
	errMalformedIndexFileName   = errors.New("malformed index is missing null terminator in file name")
	errMalformedContentOverrun  = errors.New("malformed content offset and size overrun the end of the file")
	errIndexFileNameTooBig      = errors.New("index file name exceeds the maximum length of 1024 characters")
	errIndexFileNameOverrun     = errors.New("the length of the index file overruns the end of the file")
	errIndexTooSmall            = errors.New("the index is smaller than the minimum allowed length of 12 bytes")
	errIndexBadContentReference = errors.New("index entry references to content that does not exist")
	errCursorStartAlreadyRead   = errors.New("start position has already been read in a previous chunk")
	errCursorEndAlreadyRead     = errors.New("end position has already been read in a previous chunk")
	errDupContent               = errors.New("a content entry with that name already exists")
)

// change that at runtime by setting -ldflags "-X go.mozilla.org/mar.debug=true"
var debug = "false"

func debugPrint(format string, a ...interface{}) {
	if debug == "true" {
		fmt.Printf(format, a...)
	}
}
