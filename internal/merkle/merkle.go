// Package merkle implements an RFC 6962-style binary Merkle tree over SHA-256.
//
//	leaf hash = SHA-256(0x00 || data)
//	node hash = SHA-256(0x01 || left || right)
//
// The distinct prefixes prevent a leaf from being passed off as an interior
// node (second-preimage attacks). A level with an odd number of nodes promotes
// its last node unchanged instead of duplicating it, which avoids the
// duplicate-leaf ambiguity of Bitcoin-style trees.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// ErrRootMismatch is returned when a proof does not reproduce the expected root.
var ErrRootMismatch = errors.New("computed root does not match the expected root")

// Hash is a SHA-256 digest.
type Hash [sha256.Size]byte

func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash decodes a hex-encoded 32-byte hash.
func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("invalid hex hash: %w", err)
	}

	if len(b) != len(h) {
		return h, fmt.Errorf("hash must be %d bytes, got %d", len(h), len(b))
	}

	copy(h[:], b)
	return h, nil
}

// HashLeaf returns the domain-separated leaf hash of data.
func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashNode returns the domain-separated hash of two children.
func HashNode(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Tree stores every level: Levels[0] are the leaves, the last level is [root].
type Tree struct {
	Levels [][]Hash
}

// Build constructs the tree from leaf hashes (already passed through HashLeaf).
func Build(leaves []Hash) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle: no leaves")
	}

	cur := append([]Hash(nil), leaves...)
	levels := [][]Hash{cur}
	for len(cur) > 1 {
		next := make([]Hash, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 == len(cur) {
				next = append(next, cur[i]) // odd node: promote unchanged
				continue
			}

			next = append(next, HashNode(cur[i], cur[i+1]))
		}

		levels = append(levels, next)
		cur = next
	}

	return &Tree{Levels: levels}, nil
}

// Root returns the root hash.
func (t *Tree) Root() Hash {
	return t.Levels[len(t.Levels)-1][0]
}

// Strings returns all levels as hex strings.
func (t *Tree) Strings() [][]string {
	out := make([][]string, len(t.Levels))
	for i, lvl := range t.Levels {
		out[i] = make([]string, len(lvl))
		for j, h := range lvl {
			out[i][j] = h.String()
		}
	}

	return out
}

// Side says which side of the running hash a sibling is concatenated on.
type Side string

const (
	Left  Side = "left"
	Right Side = "right"
)

// Step is one sibling on the path from a leaf to the root.
type Step struct {
	Hash string `json:"hash"`
	Side Side   `json:"side"`
}

// Prove returns the audit path for the leaf at idx.
func (t *Tree) Prove(idx int) ([]Step, error) {
	if idx < 0 || idx >= len(t.Levels[0]) {
		return nil, fmt.Errorf("leaf index %d out of range [0,%d)", idx, len(t.Levels[0]))
	}

	var steps []Step
	for lvl := 0; lvl < len(t.Levels)-1; lvl++ {
		nodes := t.Levels[lvl]
		if idx%2 == 0 {
			if idx+1 < len(nodes) {
				steps = append(steps, Step{Hash: nodes[idx+1].String(), Side: Right})
			} // else: promoted, no sibling at this level
		} else {
			steps = append(steps, Step{Hash: nodes[idx-1].String(), Side: Left})
		}

		idx /= 2
	}

	return steps, nil
}

// pathShape is the sequence of sibling sides a proof for (idx, count) must have.
func pathShape(idx, count int) []Side {
	var sides []Side
	for count > 1 {
		if idx%2 == 0 {
			if idx+1 < count {
				sides = append(sides, Right)
			}
		} else {
			sides = append(sides, Left)
		}

		idx /= 2
		count = (count + 1) / 2
	}

	return sides
}

// VerifyProof checks that leaf sits at position idx of a count-leaf tree with
// the given root. The sides in the proof must match the position, so a proof
// cannot be replayed for a different index.
func VerifyProof(leaf Hash, idx, count int, steps []Step, root Hash) error {
	if count < 1 || idx < 0 || idx >= count {
		return fmt.Errorf("leaf index %d out of range for %d leaves", idx, count)
	}

	shape := pathShape(idx, count)
	if len(shape) != len(steps) {
		return fmt.Errorf("proof has %d steps, expected %d for leaf %d of %d", len(steps), len(shape), idx, count)
	}

	cur := leaf
	for i, s := range steps {
		if s.Side != shape[i] {
			return fmt.Errorf("step %d: side %q does not match the leaf's position", i, s.Side)
		}

		sib, err := ParseHash(s.Hash)
		if err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}

		if s.Side == Left {
			cur = HashNode(sib, cur)
		} else {
			cur = HashNode(cur, sib)
		}
	}

	if cur != root {
		return ErrRootMismatch
	}

	return nil
}
