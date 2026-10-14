package merkle

import (
	"fmt"
	"testing"
)

func leavesN(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = HashLeaf(fmt.Appendf(nil, "leaf-%d", i))
	}
	return out
}

func TestShapes(t *testing.T) {
	l := leavesN(3)
	tr, err := Build(l)
	if err != nil {
		t.Fatal(err)
	}

	want := HashNode(HashNode(l[0], l[1]), l[2])
	if tr.Root() != want {
		t.Fatalf("3-leaf root: got %s want %s", tr.Root(), want)
	}

	one, _ := Build(l[:1])
	if one.Root() != l[0] {
		t.Fatal("single leaf root must equal the leaf")
	}

	if _, err := Build(nil); err == nil {
		t.Fatal("empty tree must fail")
	}
}

func TestProofsAllSizes(t *testing.T) {
	for n := 1; n <= 40; n++ {
		leaves := leavesN(n)
		tr, err := Build(leaves)
		if err != nil {
			t.Fatal(err)
		}

		root := tr.Root()
		for i := 0; i < n; i++ {
			steps, err := tr.Prove(i)
			if err != nil {
				t.Fatal(err)
			}

			if err := VerifyProof(leaves[i], i, n, steps, root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}

			if n > 1 {
				if err := VerifyProof(leaves[(i+1)%n], i, n, steps, root); err == nil {
					t.Fatalf("n=%d i=%d: accepted wrong leaf", n, i)
				}
			}
		}
	}
}
