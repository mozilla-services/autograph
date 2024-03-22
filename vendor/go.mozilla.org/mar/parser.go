package mar

import (
	"bytes"
	"encoding/binary"
)

// A parser is initialized to unmarshal a MAR file.
// It keeps a cursor of the next read position and counters to safely
// process a file and thus must not be reused between files. a parser
// is not thread safe, so use one parser per thread/goroutine.
type parser struct {
	// input data being read
	input []byte
	// current position of the cursor in the file
	cursor uint64
	// readChunks is the list of chunks that have already been read
	readChunks []chunk
}

type chunk struct {
	start, end uint64
}

func newParser(input []byte) *parser {
	return &parser{input: input}
}

// parse reads from input and converts it into the target data structure.
// it applies some basic security checks: first we're making sure we're not
// reading more than what is available in input, then we check that the chunk
// has not already been read by the parser. This prevents logic bomb attacks
// where multiple index entries reference the same chunk of content.
func (p *parser) parse(data interface{}, readLen int) error {
	startPos := p.cursor
	endPos := p.cursor + uint64(readLen)
	if uint64(len(p.input)) < endPos {
		return errInputTooShort
	}
	// verify that we're not trying to read a chunk that has already been read.
	// TODO: this is slow and memory intensive, we should use an interval tree
	for _, chunk := range p.readChunks {
		// the starting position is within a chunk already read
		if chunk.start <= startPos && chunk.end > startPos {
			debugPrint("chunk.start=%d [ startPos=%d ] chunk.end=%d\n", chunk.start, startPos, chunk.end)
			return errCursorStartAlreadyRead
		}
		// the end position is within a chunk already read
		if chunk.start < endPos && chunk.end >= endPos {
			debugPrint("chunk.start=%d [ endPos=%d ] chunk.end=%d\n", chunk.start, endPos, chunk.end)
			return errCursorEndAlreadyRead
		}
	}
	p.readChunks = append(p.readChunks, chunk{startPos, endPos})

	// move the cursor forward
	p.cursor = endPos
	r := bytes.NewReader(p.input[startPos:endPos])
	return binary.Read(r, binary.BigEndian, data)
}
