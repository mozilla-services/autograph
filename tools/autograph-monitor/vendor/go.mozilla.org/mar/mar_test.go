package mar

import (
	"bytes"
	"testing"
)

func TestMarshal(t *testing.T) {
	m := New()
	m.AddContent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "/foo/bar", 0600)
	m.AddProductInfo("caribou maurice v1.2")
	_, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnmarshal(t *testing.T) {
	var m File
	err := Unmarshal(miniMarB, &m)
	if err != nil {
		t.Fatal(err)
	}
	if m.MarID != "MAR1" {
		t.Fatalf("Expected to find MarID 'MAR1' but found %q instead", m.MarID)
	}
}

func TestUnmarshalOldMar(t *testing.T) {
	var m File
	err := Unmarshal(oldMarB, &m)
	if err != nil {
		t.Fatal(err)
	}
	if m.MarID != "MAR1" {
		t.Fatalf("Expected to find MarID 'MAR1' but found %q instead", m.MarID)
	}
	if m.Revision != 2005 {
		t.Fatalf("Expected to find revision set to 2005 but found %d instead", m.Revision)
	}
	if uint64(len(oldMarB)) != m.Size {
		t.Fatalf("Expected to find size of %d but found %d instead", uint64(len(oldMarB)), m.Size)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	m := New()
	m.AddContent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "/foo/bar", 0600)
	m.AddProductInfo("caribou maurice v1.2")
	m.AddAdditionalSection([]byte("foo bar baz"), uint32(1664))
	m.AddContent([]byte("bcdef"), "/foo/baz", 0600)
	o, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var reparsed File
	err = Unmarshal(o, &reparsed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMarshalBadMarID(t *testing.T) {
	badMar := New()
	badMar.MarID = "foo"
	_, err := badMar.Marshal()
	if err == nil {
		t.Fatalf("Expected to fail with %q but succeeded", errBadMarID)
	}
	if err != errBadMarID {
		t.Fatalf("Expected to fail with error %q but failed with error %q", errBadMarID, err)
	}
	t.Log(err)
}

func TestAddingContent(t *testing.T) {
	newMar := New()
	var (
		data         = []byte("cariboumaurice")
		name         = "/foo/bar/baz"
		flags uint32 = 640
	)
	err := newMar.AddContent(data, name, flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := newMar.Content[name]; !ok {
		t.Fatal("expected to find added content entry but didn't")
	}
	if !bytes.Equal(newMar.Content[name].Data, data) {
		t.Fatalf("expected to find data %q in content map but found %q", data, newMar.Content[name].Data)
	}
	if newMar.Index[len(newMar.Index)-1].Flags != flags {
		t.Fatalf("expected to find flags %d in index entry but found %d",
			flags, newMar.Index[len(newMar.Index)-1].Flags)
	}
	if newMar.Index[len(newMar.Index)-1].FileName != name {
		t.Fatalf("expected to find filename %q in index entry but found %q",
			name, newMar.Index[len(newMar.Index)-1].FileName)
	}
}

func TestAddingDupContent(t *testing.T) {
	newMar := New()
	var (
		data         = []byte("cariboumaurice")
		name         = "/foo/bar"
		flags uint32 = 640
	)
	err := newMar.AddContent(data, name, flags)
	if err != nil {
		t.Fatal(err)
	}
	err = newMar.AddContent(data, name, flags)
	if err == nil {
		t.Fatal("expected to fail due to duplicated content but didn't")
	}
	if err != errDupContent {
		t.Fatalf("expected to fail with duplicated content error but failed with: %v", err)
	}
	t.Log(err)
}

// $ hexdump -v -e '16/1 "_x%02X" "\n"' /tmp/o.mar | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/; s/$/ +/'
var miniMarB = []byte("\x4D\x41\x52\x31\x00\x00\x01\x7D\x00\x00\x00\x00\x00\x00\x01\x96" +
	"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x01\x00\x20\xC4\xC6\xB2" +
	"\xE0\x4F\x52\xDC\xD5\x36\xCB\x52\x22\x9B\x21\x5C\x50\x97\xAD\x0B" +
	"\xE8\x04\xEF\x61\xEE\x8B\xE8\x9C\x1E\xC0\x06\xD5\x4A\x38\x44\x50" +
	"\x21\x8C\x43\x43\x8A\xD5\x39\x8A\x8B\x5F\x06\x1A\x28\xCD\xC5\xA7" +
	"\xFF\xB9\x4E\xCB\x9B\xF4\x53\xCA\xF9\xB4\x54\xBE\xE0\x70\xE0\xE6" +
	"\xFE\x9A\x20\x0E\x64\x6D\xB5\xFF\xAB\x73\x65\x1F\x5F\xB9\xED\x84" +
	"\xFC\x42\x80\x1F\xE8\x3A\x3E\xDF\x5E\xA0\xF0\x62\x98\x81\x3C\xD4" +
	"\x92\x1C\xC2\x00\x4D\x46\xFB\x7E\x74\x51\x1E\xA5\x53\x76\xA8\x64" +
	"\x41\x9D\x91\xA9\x0B\x32\x28\xBE\xCE\xE8\x3F\xDB\x37\xAD\x84\x1E" +
	"\x65\x53\x9E\x7E\x4B\x6D\x8A\x98\x9C\x32\xE1\xA7\xE6\xC4\x54\x63" +
	"\xE8\xF4\x44\xEC\x52\x94\xA4\xED\x79\x45\xAB\x7B\xFD\xE9\xB9\x4B" +
	"\x8B\x82\x1A\xCE\x6E\x0B\xC8\xF5\x17\xB5\x09\xA2\xC4\xDC\x1E\xE8" +
	"\xE3\x86\xA5\x2F\x99\xAA\x86\xC6\x02\xDA\x28\x7B\xB9\xCF\x3C\x2D" +
	"\x10\xFE\x4A\xAA\x28\xA4\x26\x73\x00\xB2\x4C\xFF\xFE\x94\x3D\x55" +
	"\x93\xB2\x57\x6C\x3C\x86\xCD\x88\xFD\x7F\xD0\xA5\xA2\xAF\x0F\x1F" +
	"\xB8\x32\xC4\xE9\x8D\xBF\x07\xC7\xC4\xC5\x3D\xE4\x9C\x3F\x13\x17" +
	"\x45\x50\x37\x4A\xE9\x05\xBB\x50\xF4\x53\xC7\xB0\x00\x00\x00\x03" +
	"\x00\x00\x00\x40\xC4\x87\x82\x76\x33\xF7\x92\xBC\x9A\xC4\xAF\xE9" +
	"\x80\x3A\x21\x64\x5F\x4F\xDF\x62\x83\x45\xBB\xE0\xA0\xE5\xD1\x0B" +
	"\xCC\xD1\x38\xBE\x05\x1B\xC8\xEC\x54\xA6\x8E\x3B\x78\x40\xE7\xD5" +
	"\x1D\x10\xE4\xA3\x7D\x4D\xB9\x56\xB6\xB1\x40\xA8\xFC\xF8\x9B\x6A" +
	"\xE2\xC8\xEC\x6C\x00\x00\x00\x00\x61\x61\x61\x61\x61\x61\x61\x61" +
	"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x00\x00\x00" +
	"\x15\x00\x00\x01\x68\x00\x00\x00\x15\x00\x00\x02\x58\x2F\x66\x6F" +
	"\x6F\x2F\x62\x61\x72\x00")
