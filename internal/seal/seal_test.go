package seal

import (
	"bytes"
	"testing"
	"time"
)

func TestStatementAndDigest(t *testing.T) {
	ts := time.Date(2026, 9, 21, 9, 30, 3, 0, time.UTC)
	s := Statement("aa", "bb", 5, ts)
	want := "bibroot-seal-v1\nroot: aa\nsource-sha256: bb\nleaves: 5\ncreated: 2026-09-21T09:30:03Z\n"
	if s != want {
		t.Fatalf("got %q", s)
	}
	if r, err := StatementRoot(s); err != nil || r != "aa" {
		t.Fatalf("root %q err %v", r, err)
	}
	if Digest(s, []byte{1}) == Digest(s, []byte{2}) || Digest(s, nil) == Digest(s, []byte{1}) {
		t.Fatal("digest must depend on the signature")
	}
	if Digest(s, []byte{1}) != Digest(s, []byte{1}) {
		t.Fatal("digest must be deterministic")
	}
}

func TestDearmor(t *testing.T) {
	armored := "-----BEGIN PGP SIGNATURE-----\n\naGVsbG8gd29ybGQ=\n=abcd\n-----END PGP SIGNATURE-----\n"
	got, err := Dearmor(armored)
	if err != nil || !bytes.Equal(got, []byte("hello world")) {
		t.Fatalf("got %q err %v", got, err)
	}
	withHdr := "-----BEGIN PGP SIGNATURE-----\nVersion: x\n\naGVsbG8gd29ybGQ=\n=abcd\n-----END PGP SIGNATURE-----\n"
	if got, err := Dearmor(withHdr); err != nil || string(got) != "hello world" {
		t.Fatalf("with header: %q %v", got, err)
	}
	if _, err := Dearmor("garbage"); err == nil {
		t.Fatal("expected error")
	}
}
