// Package index defines the JSON manifest written by `veribib build`.
package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"veribib/internal/merkle"
)

// FormatVersion is bumped on incompatible changes to the manifest layout.
const FormatVersion = 2

const (
	StatusOK      = "ok"      // archived and committed to the tree
	StatusFailed  = "failed"  // export failed (only kept with --keep-going)
	StatusSkipped = "skipped" // entry has no URL
)

type Source struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// TreeSpec documents how hashes were computed so the manifest is self-describing.
type TreeSpec struct {
	Hash    string `json:"hash"`
	Record  string `json:"record"`
	Leaf    string `json:"leaf"`
	Node    string `json:"node"`
	OddNode string `json:"odd_node"`
	Order   string `json:"order"`
}

func DefaultTreeSpec() TreeSpec {
	return TreeSpec{
		Hash:    "sha256",
		Record:  "veribib-leaf-v1 text: key, url, pdf-sha256, fetched-at",
		Leaf:    "sha256(0x00 || record)",
		Node:    "sha256(0x01 || left || right)",
		OddNode: "promoted unchanged to the next level",
		Order:   "citation key, ascending",
	}
}

// Seal is the signed statement over the root, and the digest the heart shows.
type Seal struct {
	Statement   string `json:"statement"`
	Signature   string `json:"signature,omitempty"`   // armored detached OpenPGP signature over Statement
	Fingerprint string `json:"fingerprint,omitempty"` // signer's primary key fingerprint
	Digest      string `json:"digest"`                // hex; the 256 bits the heart encodes
}

type Entry struct {
	Key        string     `json:"key"`
	Type       string     `json:"type,omitempty"`
	Title      string     `json:"title,omitempty"`
	URL        string     `json:"url,omitempty"`
	FinalURL   string     `json:"final_url,omitempty"` // after redirects, if different
	HTTPStatus int        `json:"http_status,omitempty"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	LeafIndex  *int       `json:"leaf_index,omitempty"`
	PDF        string     `json:"pdf,omitempty"` // relative to the manifest
	PDFSize    int64      `json:"pdf_size,omitempty"`
	PDFSHA256  string     `json:"pdf_sha256,omitempty"`
	LeafHash   string     `json:"leaf_hash,omitempty"`
	FetchedAt  *time.Time `json:"fetched_at,omitempty"`
}

// LeafRecord is the canonical text a leaf commits to. It binds the citation
// key, URL and fetch time to the PDF hash, so relabelling an entry changes the
// root. strconv.Quote keeps it unambiguous whatever the key or URL contain.
func LeafRecord(key, url, pdfSHA256, fetchedAt string) []byte {
	return []byte("veribib-leaf-v1\n" +
		"key: " + strconv.Quote(key) + "\n" +
		"url: " + strconv.Quote(url) + "\n" +
		"pdf-sha256: " + pdfSHA256 + "\n" +
		"fetched-at: " + fetchedAt + "\n")
}

// Record returns the entry's leaf record.
func (e *Entry) Record() ([]byte, error) {
	if e.FetchedAt == nil {
		return nil, fmt.Errorf("entry %q has no fetched_at", e.Key)
	}

	return LeafRecord(e.Key, e.URL, e.PDFSHA256, e.FetchedAt.UTC().Format(time.RFC3339)), nil
}

// LeafHashOf computes the entry's leaf hash from its fields.
func (e *Entry) LeafHashOf() (merkle.Hash, error) {
	rec, err := e.Record()
	if err != nil {
		return merkle.Hash{}, err
	}

	return merkle.HashLeaf(rec), nil
}

type Index struct {
	Version   int        `json:"version"`
	Tool      string     `json:"tool"`
	CreatedAt time.Time  `json:"created_at"`
	Renderer  string     `json:"renderer,omitempty"`
	Source    Source     `json:"source"`
	Tree      TreeSpec   `json:"tree"`
	Root      string     `json:"root"`
	LeafCount int        `json:"leaf_count"`
	Levels    [][]string `json:"levels"` // levels[0] = leaf hashes ... last = [root]
	Seal      *Seal      `json:"seal,omitempty"`
	Entries   []Entry    `json:"entries"`
}

// Proof is a self-contained inclusion proof, including the seal so a third
// party can check the signature on the root without the rest of the manifest.
type Proof struct {
	Version   int           `json:"version"`
	Key       string        `json:"key"`
	URL       string        `json:"url"`
	FetchedAt string        `json:"fetched_at"`
	PDFSHA256 string        `json:"pdf_sha256"`
	LeafHash  string        `json:"leaf_hash"`
	LeafIndex int           `json:"leaf_index"`
	LeafCount int           `json:"leaf_count"`
	Steps     []merkle.Step `json:"steps"`
	Root      string        `json:"root"`
	Seal      *Seal         `json:"seal,omitempty"`
}

func Load(path string) (*Index, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ix Index
	if err := json.Unmarshal(b, &ix); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if ix.Version != FormatVersion {
		return nil, fmt.Errorf("%s: unsupported manifest version %d (this build reads %d)", path, ix.Version, FormatVersion)
	}

	return &ix, nil
}

func (ix *Index) Save(path string) error {
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LeafHashes returns the recorded leaf hashes of committed entries, in order.
func (ix *Index) LeafHashes() ([]merkle.Hash, error) {
	var out []merkle.Hash
	for _, e := range ix.Entries {
		if e.Status != StatusOK {
			continue
		}

		h, err := merkle.ParseHash(e.LeafHash)
		if err != nil {
			return nil, fmt.Errorf("entry %q: leaf_hash: %w", e.Key, err)
		}

		out = append(out, h)
	}

	return out, nil
}

// Rebuild rebuilds the Merkle tree from the recorded leaf hashes.
func (ix *Index) Rebuild() (*merkle.Tree, error) {
	leaves, err := ix.LeafHashes()
	if err != nil {
		return nil, err
	}

	return merkle.Build(leaves)
}

// ErrNoSeal is returned by helpers that need a seal.
var ErrNoSeal = errors.New("manifest has no seal")
