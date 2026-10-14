package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"veribib/internal/index"
	"veribib/internal/merkle"
	"veribib/internal/seal"
)

func selectEntry(ix *index.Index, sel string) (*index.Entry, error) {
	for i := range ix.Entries {
		if e := &ix.Entries[i]; e.Key == sel && e.Status == index.StatusOK {
			return e, nil
		}
	}
	if n, err := strconv.Atoi(sel); err == nil {
		for i := range ix.Entries {
			if e := &ix.Entries[i]; e.LeafIndex != nil && *e.LeafIndex == n {
				return e, nil
			}
		}
	}
	return nil, fmt.Errorf("no committed entry with key or leaf index %q", sel)
}

func makeProof(ix *index.Index, sel string) (*index.Proof, error) {
	e, err := selectEntry(ix, sel)
	if err != nil {
		return nil, err
	}
	if e.LeafIndex == nil || e.FetchedAt == nil {
		return nil, fmt.Errorf("entry %q is missing leaf_index or fetched_at", e.Key)
	}
	tree, err := ix.Rebuild()
	if err != nil {
		return nil, err
	}
	if tree.Root().String() != ix.Root {
		return nil, errors.New("manifest is inconsistent (rebuilt root differs from recorded root); run `veribib verify`")
	}
	steps, err := tree.Prove(*e.LeafIndex)
	if err != nil {
		return nil, err
	}
	return &index.Proof{
		Version:   1,
		Key:       e.Key,
		URL:       e.URL,
		FetchedAt: e.FetchedAt.UTC().Format(time.RFC3339),
		PDFSHA256: e.PDFSHA256,
		LeafHash:  e.LeafHash,
		LeafIndex: *e.LeafIndex,
		LeafCount: len(tree.Levels[0]),
		Steps:     steps,
		Root:      ix.Root,
		Seal:      ix.Seal,
	}, nil
}

func newProveCmd() *cobra.Command {
	var idxPath, outPath string
	c := &cobra.Command{
		Use:   "prove <key|leaf-index>",
		Short: "Emit a Merkle inclusion proof (with the signed seal) for one reference",
		Long: `Writes a self-contained JSON proof: the reference's key, URL, fetch time and PDF
hash, its position in the tree, the sibling hashes up to the root, and the
GPG-signed seal over that root. Anyone holding the proof and the PDF can
confirm the PDF is part of the sealed bibliography with "veribib check".`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ix, _, err := loadIndex(idxPath)
			if err != nil {
				return err
			}
			p, err := makeProof(ix, args[0])
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
			if outPath == "" || outPath == "-" {
				_, err = cmd.OutOrStdout().Write(data)
				return err
			}
			return os.WriteFile(outPath, data, 0o644)
		},
	}
	addIndexFlag(c, &idxPath)
	c.Flags().StringVarP(&outPath, "out", "o", "", "write the proof here instead of stdout")
	return c
}

func newCheckCmd() *cobra.Command {
	var (
		idxPath, proofPath, file, wantRoot string
		pubkey, fingerprint, gpgBin        string
		skipSig                            bool
	)
	c := &cobra.Command{
		Use:   "check [key]",
		Short: "Check that a PDF is included in a sealed bibliography, using a Merkle proof",
		Long: `Inclusion check, from a proof file or straight from the manifest:

  veribib check --proof smith2020.proof.json --file smith2020.pdf --fingerprint <fpr>
  veribib check smith2020 --file ./some-copy.pdf --pubkey me.asc

--file re-hashes a PDF you hold and confirms it is the committed one. If the
proof carries a signed seal, the GPG signature over the root is verified too
(--pubkey / --fingerprint say whose signature you accept). Otherwise pass
--root with a root from a trusted source.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var p *index.Proof
			switch {
			case proofPath != "":
				b, err := os.ReadFile(proofPath)
				if err != nil {
					return err
				}

				p = new(index.Proof)
				if err := json.Unmarshal(b, p); err != nil {
					return fmt.Errorf("%s: %w", proofPath, err)
				}

			case len(args) == 1:
				ix, _, err := loadIndex(idxPath)
				if err != nil {
					return err
				}

				if p, err = makeProof(ix, args[0]); err != nil {
					return err
				}

			default:
				return errors.New("give a citation key (uses the manifest) or --proof FILE")

			}

			pdfSum := p.PDFSHA256
			if file != "" {
				sum, _, err := sha256File(file)
				if err != nil {
					return err
				}

				if p.PDFSHA256 != "" && sum != p.PDFSHA256 {
					return fmt.Errorf("%s hashes to %s, but the proof commits to %s", file, short(sum), short(p.PDFSHA256))
				}

				pdfSum = sum
			}

			if pdfSum == "" {
				return errors.New("proof has no pdf_sha256; pass --file")
			}

			leaf := merkle.HashLeaf(index.LeafRecord(p.Key, p.URL, pdfSum, p.FetchedAt))
			if p.LeafHash != "" && leaf.String() != p.LeafHash {
				return errors.New("proof is inconsistent: key, url, fetched_at and pdf hash do not reproduce leaf_hash")
			}

			rootHex := p.Root
			if wantRoot != "" {
				rootHex = strings.TrimSpace(wantRoot)
			}

			root, err := merkle.ParseHash(rootHex)
			if err != nil {
				return fmt.Errorf("root: %w", err)
			}

			if err := merkle.VerifyProof(leaf, p.LeafIndex, p.LeafCount, p.Steps, root); err != nil {
				return fmt.Errorf("NOT included: %w", err)
			}

			out := cmd.OutOrStdout()
			signer := ""
			if p.Seal != nil && p.Seal.Signature != "" && !skipSig {
				stRoot, err := seal.StatementRoot(p.Seal.Statement)
				if err != nil {
					return err
				}

				if stRoot != root.String() {
					return errors.New("the signed statement is for a different root than the proof")
				}

				g := seal.GPG{Bin: gpgBin}
				if err := g.Available(); err != nil {
					return err
				}

				res, err := g.Verify(pubkey, p.Seal.Statement, p.Seal.Signature)
				if err != nil {
					return fmt.Errorf("seal signature: %w", err)
				}

				if fingerprint != "" && !seal.MatchFingerprint(fingerprint, res) {
					return fmt.Errorf("sealed by %s, not the required %s", res.Primary, fingerprint)
				}

				signer = res.Primary
			}

			name := p.Key
			if name == "" {
				name = "leaf"
			}

			fmt.Fprintf(out, "included  %s is leaf %d of %d under root %s\n", name, p.LeafIndex, p.LeafCount, root)
			switch {
			case signer != "":
				fmt.Fprintf(out, "sealed    root signed by %s\n", signer)
				if pubkey == "" && fingerprint == "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "note: no --pubkey/--fingerprint given: any key in your keyring is accepted as the signer")
				}

			case wantRoot == "":
				fmt.Fprintln(cmd.ErrOrStderr(), "note: the root came from the proof itself and was not signature-checked; pass --root or a signed proof")
			}

			return nil
		},
	}

	addIndexFlag(c, &idxPath)
	f := c.Flags()
	f.StringVar(&proofPath, "proof", "", "proof file produced by `veribib prove`")
	f.StringVar(&file, "file", "", "PDF to hash and check")
	f.StringVar(&wantRoot, "root", "", "trusted root hash (hex)")
	f.StringVar(&pubkey, "pubkey", "", "signer's public key file; only this key can satisfy the signature check")
	f.StringVar(&fingerprint, "fingerprint", "", "required signer fingerprint (or long key ID)")
	f.BoolVar(&skipSig, "skip-sig", false, "do not verify the GPG signature")
	f.StringVar(&gpgBin, "gpg", "", "gpg binary (default: gpg)")
	return c
}
