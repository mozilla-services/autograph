package mar

import (
	"bytes"
	"testing"
)

func TestParser(t *testing.T) {
	var input = []byte("foobarbaz")
	p := newParser(input)
	output := make([]byte, 9, 9)
	err := p.parse(output, 9)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, output) {
		t.Fatalf("expected output to match input %q but got %q instead", input, output)
	}
}

func TestParserInputTooShort(t *testing.T) {
	input := []byte("foobarbaz")
	p := newParser(input)
	output := make([]byte, 20, 20)
	err := p.parse(output, 20)
	if err == nil {
		t.Fatal("expected to fail with input too short but succeeded")
	}
	if err != errInputTooShort {
		t.Fatalf("expected to fail with input too short but got %v", err)
	}
	t.Log(err)
}

func TestParserReadTwice(t *testing.T) {
	input := []byte("foobarbaz")
	p := newParser(input)
	output := make([]byte, 9, 9)
	err := p.parse(output, 9)
	if err != nil {
		t.Fatal(err)
	}
	// the second read of the same chunk must fail
	p.cursor = 0
	err = p.parse(output, 9)
	if err == nil {
		t.Fatal("expected to fail with duplicate read but succeeded")
	}
	if err != errCursorStartAlreadyRead {
		t.Fatalf("expected to fail with cursor start already read but failed with: %v", err)
	}
	t.Log(err)
}

func TestParserReadInside(t *testing.T) {
	input := []byte("foobarbaz")
	p := newParser(input)
	output := make([]byte, 9, 9)
	err := p.parse(output, 9)
	if err != nil {
		t.Fatal(err)
	}
	// the second read of a smaller chunk inside the chunk
	// previously read must fail
	output2 := make([]byte, 4, 4)
	p.cursor = 4
	err = p.parse(output2, 4)
	if err == nil {
		t.Fatal("expected to fail with duplicate read but succeeded")
	}
	if err != errCursorStartAlreadyRead {
		t.Fatalf("expected to fail with cursor start already read but failed with: %v", err)
	}
	t.Log(err)
}

func TestParserReadEnd(t *testing.T) {
	input := []byte("aaaaaaaaafoobarbaz")
	p := newParser(input)
	output := make([]byte, 9, 9)
	p.cursor = 9
	err := p.parse(output, 9)
	if err != nil {
		t.Fatal(err)
	}
	// the second read of a smaller chunk inside the chunk
	// previously read must fail
	p.cursor = 4
	err = p.parse(output, 9)
	if err == nil {
		t.Fatal("expected to fail with duplicate read but succeeded")
	}
	if err != errCursorEndAlreadyRead {
		t.Fatalf("expected to fail with cursor end already read but failed with: %v", err)
	}
	t.Log(err)
}
