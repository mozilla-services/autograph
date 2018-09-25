package mar

import (
	"testing"
)

// firefox's signmar is happy to reference the same content block from
// multiple index entries, which could be used as a zip bomb to create
// a fraudulent mar file that decompresses to many times its original
// size. Margo hash checks in place to refuse to unmarshal such files.
// see also:
//	BLRG-PT-18-013: DoS by Overly Large Files in MAR
//	https://bugzilla.mozilla.org/show_bug.cgi?id=1468556
func TestDosByLargeFile(t *testing.T) {
	dosMar := File{
		MarID: "MAR1",
		Content: map[string]Entry{
			"/foo/bar": {
				Data: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			},
		},
		Index: []IndexEntry{
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
			{IndexEntryHeader{Flags: 0640}, "/foo/bar"},
		},
	}
	o, err := dosMar.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var reparsed File
	err = Unmarshal(o, &reparsed)
	if err == nil {
		t.Fatal("expected to fail with duplicate content read but succeeded", err)
	}
	if err != errCursorStartAlreadyRead {
		t.Fatalf("expected to fail with duplicate content read but failed with: %v", err)
	}
}

func TestBadIndexReference(t *testing.T) {
	dosMar := File{
		MarID: "MAR1",
		Content: map[string]Entry{
			"/foo/bar": {
				Data: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			},
		},
		Index: []IndexEntry{
			{IndexEntryHeader{Flags: 0640}, "/does/not/exist"},
		},
	}
	_, err := dosMar.Marshal()
	if err == nil {
		t.Fatalf("expected to fail with %q but succeeded", errIndexBadContentReference)
	}
	if err != errIndexBadContentReference {
		t.Fatalf("expected to fail with %q but failed with %v", errIndexBadContentReference, err)
	}
}

func TestEmptyIndex(t *testing.T) {
	var f File
	var emptyIndex = []byte("MAR1\x00\x00\x00\x88000000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000000000000000000")
	err := Unmarshal(emptyIndex, &f)
	if err == nil {
		t.Fatalf("expected to fail with %q but succeeded", errIndexTooSmall)
	}
	if err != errIndexTooSmall {
		t.Fatalf("expected to fail with %q but failed with %v", errIndexTooSmall, err)
	}
}
