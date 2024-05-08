package mar // import "go.mozilla.org/mar"

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// MarIDLen is the length of the MAR ID header.
	// A MAR file starts with 4 bytes containing the MAR ID, typically "MAR1"
	MarIDLen = 4

	// OffsetToIndexLen is the length of the offset to index value.
	// The MAR file continues with the position of the index relative
	// to the beginning of the file
	OffsetToIndexLen = 4

	// FileSizeLen is a uint64 that contains the total size of the MAR in bytes
	FileSizeLen = 8

	// SignaturesHeaderLen is the length of the signatures header that
	// contains the number of signatures in the MAR
	SignaturesHeaderLen = 4

	// SignatureEntryHeaderLen is the length of the header of each signature entry
	// Each signature entry contains an algorithm and a size, each on 4 bytes
	SignatureEntryHeaderLen = 8

	// AdditionalSectionsHeaderLen is the length of the additional sections header
	// Optional additional sections can be added, their number is stored on 4 bytes
	AdditionalSectionsHeaderLen = 4

	// AdditionalSectionsEntryHeaderLen is the length of the header of each
	// additional section, containing a block size and identifier on 4 bytes each
	AdditionalSectionsEntryHeaderLen = 8

	// IndexHeaderLen is the length of the index header
	// The size of the index is stored in a header on 4 bytes
	IndexHeaderLen = 4

	// IndexEntryHeaderLen is the length of the header of each index entry.
	// Each index entry contains a header with an offset to content (relative to
	// the beginning of the file), a content size and permission flags,
	// each on 4 bytes
	IndexEntryHeaderLen = 12

	// BlockIDProductInfo is the ID of a Product Information Block
	// in additional sections
	BlockIDProductInfo = 1
)

// File is a parsed MAR file.
type File struct {
	MarID                    string                   `json:"mar_id" yaml:"mar_id"`
	OffsetToIndex            uint32                   `json:"offset_to_index" yaml:"offset_to_index"`
	Size                     uint64                   `json:"size" yaml:"size"`
	ProductInformation       string                   `json:"product_information,omitempty" yaml:"product_information,omitempty"`
	SignaturesHeader         SignaturesHeader         `json:"signature_header" yaml:"signature_header"`
	Signatures               []Signature              `json:"signatures" yaml:"signatures"`
	AdditionalSectionsHeader AdditionalSectionsHeader `json:"additional_sections_header" yaml:"additional_sections_header"`
	AdditionalSections       []AdditionalSection      `json:"additional_sections" yaml:"additional_sections"`
	IndexHeader              IndexHeader              `json:"index_header" yaml:"index_header"`
	Index                    []IndexEntry             `json:"index" yaml:"index"`
	Content                  map[string]Entry         `json:"-" yaml:"-"`
	Revision                 int                      `json:"revision" yaml:"revision"`

	// marshalForSignature is used to tell the marshaller to exclude
	// signature data when preparing a file for signing
	marshalForSignature bool
}

// SignaturesHeader contains the number of signatures in the MAR file
type SignaturesHeader struct {
	// NumSignatures is the count of signatures
	NumSignatures uint32 `json:"num_signatures" yaml:"num_signatures"`
}

// Signature is a single signature on the MAR file
type Signature struct {
	SignatureEntryHeader `json:"signature_entry" yaml:"signature_entry"`
	// Algorithm is a string that represents the signing algorithm name
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	// Data is the signature bytes
	Data []byte `json:"data" yaml:"-"`

	// privateKey is a RSA private key used for signing the MAR file
	privateKey crypto.PrivateKey
}

// SignatureEntryHeader is the header of each signature entry that
// contains the Algorithm ID and Size
type SignatureEntryHeader struct {
	// AlgorithmID is either SigAlgRsaPkcs1Sha1 (1) or SigAlgRsaPkcs1Sha384 (2)
	AlgorithmID uint32 `json:"algorithm_id" yaml:"algorithm_id"`
	// Size is the size of the signature data in bytes
	Size uint32 `json:"size" yaml:"size"`
}

// AdditionalSectionsHeader contains the number of additional sections in the MAR file
type AdditionalSectionsHeader struct {
	// NumAdditionalSections is the count of additional sections
	NumAdditionalSections uint32 `json:"num_additional_sections" yaml:"num_additional_sections"`
}

// AdditionalSection is a single additional section on the MAR file
type AdditionalSection struct {
	AdditionalSectionEntryHeader `json:"additional_section_entry" yaml:"additional_section_entry"`
	// Data contains the additional section data
	Data []byte `json:"data" yaml:"-"`
}

// AdditionalSectionEntryHeader is the header of each additional section
// that contains the block size and ID
type AdditionalSectionEntryHeader struct {
	// BlockSize is the size of the additional section in bytes, including
	// the header and the following data. You need to substract the header length
	// to parse just the data..
	BlockSize uint32 `json:"block_size" yaml:"block_size"`
	// BlockID is the identifier of the block.
	// BlockIDProductInfo (1) for Product Information
	BlockID uint32 `json:"block_id" yaml:"block_id"`
}

// Entry is a single file entry in the MAR file. If IsCompressed is true, the content
// is compressed with xz
type Entry struct {
	// Data contains the raw data of the entry. It may still be compressed.
	Data []byte `json:"data" yaml:"-"`
	// IsCompressed is set to true if the Data is compressed with xz
	IsCompressed bool `json:"is_compressed" yaml:"-"`
}

// IndexHeader is the size of the index section of the MAR file, in bytes
type IndexHeader struct {
	// Size is the size of the index entries, in bytes
	Size uint32 `json:"size" yaml:"size"`
}

// IndexEntry is a single index entry in the MAR index
type IndexEntry struct {
	IndexEntryHeader `json:"index_entry" yaml:"index_entry"`
	// Filename is the name of the file being indexed
	FileName string `json:"file_name" yaml:"file_name"`
}

// IndexEntryHeader is the header of each index entry
// that contains the offset to content, size and flags
type IndexEntryHeader struct {
	// OffsetToContent is the position in bytes of the entry data relative
	// to the start of the MAR file
	OffsetToContent uint32 `json:"offset_to_content" yaml:"offset_to_content"`
	// Size is the size of the data in bytes
	Size uint32 `json:"size" yaml:"size"`
	// Flags is the file permission bits in standard unix-style format
	Flags uint32 `json:"flags" yaml:"flags"`
}

// New returns an initialized MAR data structure
func New() *File {
	return &File{
		MarID:    "MAR1",
		Content:  make(map[string]Entry),
		Revision: 2012,
	}
}

// Unmarshal takes an unparsed MAR file as input and parses it into a File struct.
// The MAR format is described at https://wiki.mozilla.org/Software_Update:MAR
// but don't believe everything it says, because the format has changed over the
// years to support more fields, and of course the MarID has not changed since.
// There's a bit of magic in this function to detect which version of a MAR we're
// dealing with, and store that in the Revision field of the file. 2005 is an old
// MAR, 2012 is a current one with signatures and additional sections.
func Unmarshal(input []byte, file *File) error {
	switch file.Size = uint64(len(input)); {
	case file.Size < limitMinFileSize:
		debugPrint("input=%d < limit=%d\n", file.Size, limitMinFileSize)
		return errTooSmall
	case file.Size > limitMaxFileSize:
		debugPrint("input=%d > limit=%d\n", file.Size, limitMaxFileSize)
		return errTooBig
	}

	p := newParser(input)

	//  A modern MAR is composed of the following fields, in bytes:
	//  0                   1
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...............
	// | MAR ID| Offset|Total FileSize |Signatures|Add.Section|Content|Index
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...............
	//
	// except if we're dealing with an old MAR, in which case it's
	//  0                   1
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.................
	// | MAR ID| Offset|...Content...|IdxSize|[Idx Entries]
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.................
	//
	// We need to detect which type of MAR we're dealing with, so first
	// we parse the MarID and Offset, then we jump to the first index
	// entry to see if its offset to content starts right after the header,
	// in which case we're dealing with an old MAR, otherwise it's a new one.

	// Parse the MAR ID
	marid := make([]byte, MarIDLen, MarIDLen)
	err := p.parse(&marid, MarIDLen)
	if err != nil {
		return fmt.Errorf("mar id parsing failed: %v", err)
	}
	file.MarID = string(marid)
	if file.MarID != "MAR1" {
		return errBadMarID
	}

	// Parse the offset to the index
	err = p.parse(&file.OffsetToIndex, OffsetToIndexLen)
	if err != nil {
		return fmt.Errorf("offset parsing failed: %v", err)
	}

	// parse the index
	p.cursor = uint64(file.OffsetToIndex)
	err = p.parse(&file.IndexHeader, IndexHeaderLen)
	if err != nil {
		return fmt.Errorf("index header parsing failed: %v", err)
	}
	if file.IndexHeader.Size < IndexEntryHeaderLen {
		return errIndexTooSmall
	}

	for i := 0; ; i++ {
		var (
			idxEntryHeader IndexEntryHeader
			idxEntry       IndexEntry
		)
		// don't read beyond the end of the file
		if uint64(p.cursor) >= file.Size {
			break
		}
		err = p.parse(&idxEntryHeader, IndexEntryHeaderLen)
		if err != nil {
			return fmt.Errorf("index entry parsing failed: %v", err)
		}

		idxEntry.Size = idxEntryHeader.Size
		idxEntry.Flags = idxEntryHeader.Flags
		idxEntry.OffsetToContent = idxEntryHeader.OffsetToContent
		if uint64(idxEntry.OffsetToContent+idxEntry.Size) > file.Size {
			return errMalformedContentOverrun
		}

		endNamePos := bytes.Index(input[p.cursor:], []byte("\x00"))

		// apply some sanity checking on filenames.
		// they shouldn't be longer than 1024 characters, and their length
		// can't overrun the size of the input
		if endNamePos < 0 {
			return errMalformedIndexFileName
		}
		if endNamePos > limitFileNameLength {
			return errIndexFileNameTooBig
		}
		if (p.cursor + uint64(endNamePos)) > file.Size {
			return errIndexFileNameOverrun

		}
		idxEntry.FileName = string(input[p.cursor : p.cursor+uint64(endNamePos)])

		// manually move the cursor to the end of the filename
		p.cursor = p.cursor + uint64(endNamePos) + 1

		file.Index = append(file.Index, idxEntry)
	}

	// evaluate the first index entry and if the offset to content is set to byte 8,
	// we have an old MAR that has no signature or additional sections
	if len(file.Index) < 1 {
		return errIndexTooSmall
	}
	if file.Index[0].OffsetToContent == MarIDLen+OffsetToIndexLen {
		file.Revision = 2005
		// use the input len as a file size since we don't have one in the headers
		file.Size = uint64(len(input))
		// skip the signature and additonal section parsing, we have none
		goto parseContent
	}

	// go back to the beginning of the signatures block
	p.cursor = MarIDLen + OffsetToIndexLen
	file.Revision = 2012

	// Parse the total file size header
	err = p.parse(&file.Size, FileSizeLen)
	if err != nil {
		return fmt.Errorf("total file size header parsing failed: %v", err)
	}
	// make sure the file size is consistent with the offsets and index len
	if file.Size != uint64(file.OffsetToIndex+file.IndexHeader.Size+IndexHeaderLen) {
		debugPrint("filesize=%d; offset to index=%d; index size=%d\n",
			file.Size, file.OffsetToIndex, file.IndexHeader.Size)
		return errMalformedFileSize
	}
	// Parse the signatures header
	err = p.parse(&file.SignaturesHeader, SignaturesHeaderLen)
	if err != nil {
		return fmt.Errorf("total file size header parsing failed: %v", err)
	}

	// Parse each signature and append them to the File
	for i := uint32(0); i < file.SignaturesHeader.NumSignatures; i++ {
		var (
			sigEntryHeader SignatureEntryHeader
			sig            Signature
		)

		err = p.parse(&sigEntryHeader, SignatureEntryHeaderLen)
		if err != nil {
			return fmt.Errorf("signature entry header parsing failed: %v", err)
		}

		sig.AlgorithmID = sigEntryHeader.AlgorithmID
		sig.Size = sigEntryHeader.Size
		if sig.Size > limitMaxSignatureSize {
			return errSignatureTooBig
		}
		sig.Algorithm = getSigAlgNameFromID(sig.AlgorithmID)
		if sig.Algorithm == "unknown" {
			return errSignatureUnknown
		}

		sig.Data = make([]byte, sig.Size, sig.Size)
		err = p.parse(&sig.Data, int(sig.Size))
		if err != nil {
			return fmt.Errorf("signature data parsing failed: %v", err)
		}
		file.Signatures = append(file.Signatures, sig)
	}

	// Parse the additional sections header
	err = p.parse(&file.AdditionalSectionsHeader, AdditionalSectionsHeaderLen)
	if err != nil {
		return fmt.Errorf("additional section header parsing failed: %v", err)
	}

	// Parse each additional section and append them to the File
	for i := uint32(0); i < file.AdditionalSectionsHeader.NumAdditionalSections; i++ {
		var (
			ash AdditionalSectionEntryHeader
			as  AdditionalSection
		)

		err = p.parse(&ash, AdditionalSectionsEntryHeaderLen)
		if err != nil {
			return fmt.Errorf("additional section entry header parsing failed: %v", err)
		}

		as.BlockID = ash.BlockID
		as.BlockSize = ash.BlockSize
		if as.BlockSize > limitMaxAdditionalDataSize {
			debugPrint("block size %d is larger than limit %d\n", as.BlockSize, limitMaxAdditionalDataSize)
			return errAdditionalDataTooBig
		}
		dataSize := ash.BlockSize - AdditionalSectionsEntryHeaderLen
		as.Data = make([]byte, dataSize, dataSize)

		err = p.parse(&as.Data, int(dataSize))
		if err != nil {
			return fmt.Errorf("additional section data parsing failed: %v", err)
		}

		switch ash.BlockID {
		case BlockIDProductInfo:
			// remove all the null bytes from the product info string
			file.ProductInformation = fmt.Sprintf("%s", strings.Replace(strings.Trim(string(as.Data), "\x00"), "\x00", " ", -1))
		}
		file.AdditionalSections = append(file.AdditionalSections, as)
	}

	// parse the content
parseContent:
	file.Content = make(map[string]Entry)
	for _, idxEntry := range file.Index {
		var entry Entry
		// copy the content from the input buffer into the entry data.
		// security checks were already done when parsing the index, so
		// we know this is safe
		entry.Data = make([]byte, idxEntry.Size, idxEntry.Size)
		p.cursor = uint64(idxEntry.OffsetToContent)
		err = p.parse(entry.Data, int(idxEntry.Size))
		if err != nil {
			return err
		}
		// move the cursor to the location of the content
		// files in MAR archives can be compressed with xz, so we test
		// the first 6 bytes to check for that
		//                                                             /---XZ's magic number--\
		if len(entry.Data) > 6 && bytes.Equal(entry.Data[0:6], []byte("\xFD\x37\x7A\x58\x5A\x00")) {
			entry.IsCompressed = true
		}
		if _, ok := file.Content[idxEntry.FileName]; ok {
			return fmt.Errorf("file named %q already exists in the archive, duplicates are not permitted", idxEntry.FileName)
		}
		file.Content[idxEntry.FileName] = entry
	}
	return nil
}

// Marshal returns an []byte of the marshalled MAR file that follows the
// expected MAR binary format. It expects a properly constructed MAR object
// with the index and content already in place. It also should already be
// signed, as the output of this function can no longer be modified.
func (file *File) Marshal() ([]byte, error) {
	var (
		offsetToContent, sigSizes int
		output                    []byte
	)
	buf := new(bytes.Buffer)

	// Write the headers
	if file.MarID != "MAR1" {
		return nil, errBadMarID
	}
	err := binary.Write(buf, binary.BigEndian, []byte(file.MarID))
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, file.OffsetToIndex)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, file.Size)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, file.SignaturesHeader)
	if err != nil {
		return nil, err
	}
	// start the cursor after the headers
	offsetToContent = MarIDLen + OffsetToIndexLen + FileSizeLen + SignaturesHeaderLen

	// Write the signatures
	for _, sig := range file.Signatures {
		err = binary.Write(buf, binary.BigEndian, sig.AlgorithmID)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, sig.Size)
		if err != nil {
			return nil, err
		}
		// If we're marshalling for signature, skip the actual signature data
		// from the output, but count it in the total size and offsets
		if file.marshalForSignature {
			// reset the flag when the function exits
			defer func() { file.marshalForSignature = false }()
			// even though we're not writing the signature, we still need
			// to account for its size in the offsets and total
			sigSizes += int(sig.Size)
		} else {
			// if we're not preparing a signable block,
			// include the signature data
			_, err = buf.Write(sig.Data)
			if err != nil {
				return nil, err
			}
		}
		offsetToContent += SignatureEntryHeaderLen + int(sig.Size)
	}
	err = binary.Write(buf, binary.BigEndian, file.AdditionalSectionsHeader)
	if err != nil {
		return nil, err
	}
	offsetToContent += AdditionalSectionsHeaderLen
	for _, as := range file.AdditionalSections {
		err = binary.Write(buf, binary.BigEndian, as.BlockSize)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, as.BlockID)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, as.Data)
		if err != nil {
			return nil, err
		}
		offsetToContent += int(as.BlockSize)
	}

	// We need to create the index that will go to the end of the file.
	// For that, we create a new buffer where index entries will be written to,
	// then process each index entry, add them to the index buffer and add the
	// content to the main buffer.
	idxBuf := new(bytes.Buffer)
	for _, idx := range file.Index {
		if _, ok := file.Content[idx.FileName]; !ok {
			return nil, errIndexBadContentReference
		}
		// Write the index entry piece by piece:
		// first we put the offset to content
		// then the size of the content
		// then the permission flags
		// and finally the filename, with a null terminator
		err = binary.Write(idxBuf, binary.BigEndian, uint32(offsetToContent))
		if err != nil {
			return nil, err
		}
		err = binary.Write(idxBuf, binary.BigEndian, uint32(len(file.Content[idx.FileName].Data)))
		if err != nil {
			return nil, err
		}
		err = binary.Write(idxBuf, binary.BigEndian, idx.Flags)
		if err != nil {
			return nil, err
		}
		err = binary.Write(idxBuf, binary.BigEndian, []byte(idx.FileName))
		if err != nil {
			return nil, err
		}
		_, err = idxBuf.Write([]byte("\x00"))
		if err != nil {
			return nil, err
		}
		// with the index in place, we append the content to the main buffer
		// and increase the value of offsetToContent to reflect how far into
		// the main buffer we will be writing next
		buf.Write(file.Content[idx.FileName].Data)
		offsetToContent += int(idx.Size)
	}
	// rewrite the index header size now that we know it's final size
	file.IndexHeader.Size = uint32(idxBuf.Len())
	finalIdxBuf := new(bytes.Buffer)
	err = binary.Write(finalIdxBuf, binary.BigEndian, file.IndexHeader)
	if err != nil {
		return nil, err
	}
	finalIdxBuf.Write(idxBuf.Bytes())

	output = append(output, buf.Bytes()...)
	output = append(output, finalIdxBuf.Bytes()...)

	// update the total size directly in the output data.
	// this is basically the size of both the main and index buffer, but also the
	// size of any future signatures if we're marshalling for signature (otherwise
	// sigSizes is zero because the signature data is already in buf)
	file.Size = uint64(buf.Len() + finalIdxBuf.Len() + sigSizes)
	fsizeBuf := new(bytes.Buffer)
	err = binary.Write(fsizeBuf, binary.BigEndian, file.Size)
	if err != nil {
		return nil, err
	}
	copy(output[MarIDLen+OffsetToIndexLen:MarIDLen+OffsetToIndexLen+8], fsizeBuf.Bytes())

	// update the offset to index directly in the output data
	file.OffsetToIndex = uint32(buf.Len() + sigSizes)
	if file.OffsetToIndex < uint32(limitMinFileSize-IndexHeaderLen) {
		return nil, errOffsetTooSmall
	}
	offsetBuf := new(bytes.Buffer)
	err = binary.Write(offsetBuf, binary.BigEndian, file.OffsetToIndex)
	if err != nil {
		return nil, err
	}
	copy(output[MarIDLen:MarIDLen+OffsetToIndexLen], offsetBuf.Bytes())

	return output, nil
}

// AddContent stores content in a MAR and creates a new entry in the index
func (file *File) AddContent(data []byte, name string, flags uint32) error {
	if _, ok := file.Content[name]; ok {
		return errDupContent
	}
	file.Content[name] = Entry{Data: data}
	file.Index = append(file.Index, IndexEntry{
		IndexEntryHeader{
			Size:  uint32(len(data)),
			Flags: flags,
		},
		name,
	})
	return nil
}

// AddAdditionalSection stores data in the additional section of a MAR
func (file *File) AddAdditionalSection(data []byte, blockID uint32) {
	file.AdditionalSections = append(file.AdditionalSections, AdditionalSection{
		AdditionalSectionEntryHeader{
			BlockSize: uint32(len(data) + AdditionalSectionsEntryHeaderLen),
			BlockID:   blockID,
		},
		data,
	})
	file.AdditionalSectionsHeader.NumAdditionalSections++
}

// AddProductInfo adds a product information string (typically, the version of firefox)
// into the additional sections of a MAR
func (file *File) AddProductInfo(productInfo string) {
	file.AddAdditionalSection([]byte(productInfo), BlockIDProductInfo)
}
