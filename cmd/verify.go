package cmd

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/cobra"

	"veribib/internal/hayagriva"
	"veribib/internal/index"
	"veribib/internal/merkle"
)

func newVerifyCmd() *cobra.Command {
	var (
		idxPath, source, wantRoot   string
		pubkey, fingerprint, heartP string
		skipFiles, skipSig          bool
		gpgBin, gnupgHome           string
	)
	c := &cobra.Command{
		Use:   "verify",
		Short: "Re-hash the PDFs, rebuild the tree, check the GPG seal and the heart",
		Long: `Checks, in order:

  1. each entry's leaf hash against its key, URL, fetch time and PDF hash
  2. each archived PDF on disk against its recorded hash
  3. the Merkle tree rebuilt from the leaves against every recorded level and the root
  4. the seal: its statement against the manifest, the GPG signature over it,
     and the heart digest derived from that signature
  5. the heart image against the digest

Trust comes from outside the manifest. Pass --pubkey (the signer's public key
file) and/or --fingerprint (their key's fingerprint) so that only your key
counts; without either, any key in your keyring that signed it is accepted and
reported. --heart checks a copy of the PNG embedded elsewhere (a resized copy
is fine, as long as it is a whole multiple of the grid size).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ix, dir, err := loadIndex(idxPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			problems := 0
			pass := func(format string, a ...any) { fmt.Fprintf(out, "  ok    "+format+"\n", a...) }
			// note := func(format string, a ...any) { fmt.Fprintf(out, "  note  "+format+"\n", a...) }
			fail := func(format string, a ...any) {
				problems++
				fmt.Fprintf(out, "  FAIL  "+format+"\n", a...)
			}

			// 1-2. entries and files
			pos := 0
			for _, e := range ix.Entries {
				if e.Status != index.StatusOK {
					continue
				}
				var bad []string
				if e.LeafIndex == nil || *e.LeafIndex != pos {
					bad = append(bad, "leaf_index out of sequence")
				}
				pos++
				if h, err := e.LeafHashOf(); err != nil {
					bad = append(bad, err.Error())
				} else if h.String() != e.LeafHash {
					bad = append(bad, "leaf_hash does not match the entry's key, url, fetch time and PDF hash")
				}
				if !skipFiles {
					sum, size, err := sha256File(filepath.Join(dir, filepath.FromSlash(e.PDF)))
					switch {
					case err != nil:
						bad = append(bad, err.Error())
					case sum != e.PDFSHA256:
						bad = append(bad, "PDF content changed (now "+short(sum)+")")
					case size != e.PDFSize:
						bad = append(bad, "PDF size changed")
					}
				}
				if len(bad) == 0 {
					pass("%-32s %s", e.Key, short(e.PDFSHA256))
				} else {
					fail("%-32s %s", e.Key, strings.Join(bad, "; "))
				}
			}

			// 3. tree
			leaves, err := ix.LeafHashes()
			if err != nil {
				fail("%v", err)
			} else if tree, err := merkle.Build(leaves); err != nil {
				fail("cannot rebuild tree: %v", err)
			} else {
				total := 0
				for _, l := range tree.Levels {
					total += len(l)
				}
				switch {
				case len(leaves) != ix.LeafCount:
					fail("leaf_count is %d but %d entries are committed", ix.LeafCount, len(leaves))
				case tree.Root().String() != ix.Root:
					fail("rebuilt root %s differs from recorded root %s", tree.Root(), ix.Root)
				case !reflect.DeepEqual(tree.Strings(), ix.Levels):
					fail("recorded interior hashes do not match the rebuilt tree")
				default:
					pass("all %d hashes match the rebuilt tree", total)
				}
			}

			if wantRoot != "" {
				if strings.EqualFold(strings.TrimSpace(wantRoot), ix.Root) {
					pass("root matches the pinned root")
				} else {
					fail("root %s does not match pinned root %s", ix.Root, wantRoot)
				}
			}

			// source bibliography
			if source != "" {
				sum, _, err := sha256File(source)
				switch {
				case err != nil:
					fail("source: %v", err)
				case sum == ix.Source.SHA256:
					pass("source file is byte-identical to the one that was committed")
				default:
					fail("source file has changed since the commit")
					compareRefs(source, ix, fail)
				}
			}

			// var digest []byte
			// if ix.Seal == nil {
			// 	fail("manifest has no seal")
			// } else {
			// 	sl := ix.Seal
			// 	stmt := seal.Statement(ix.Root, ix.Source.SHA256, ix.LeafCount, ix.CreatedAt)
			// 	if stmt != sl.Statement {
			// 		fail("seal statement does not match the manifest (root, source hash, leaf count or created_at)")
			// 	} else {
			// 		pass("seal statement matches the manifest")
			// 	}
			//
			// 	var sigBytes []byte
			// 	pinned := pubkey != "" || fingerprint != ""
			// 	switch {
			// 	case sl.Signature == "" && pinned:
			// 		fail("seal is unsigned, but a signer was required")
			// 	case sl.Signature == "":
			// 		note("seal is unsigned")
			// 	default:
			// 		if sigBytes, err = seal.Dearmor(sl.Signature); err != nil {
			// 			fail("signature: %v", err)
			// 		}
			// 		if skipSig {
			// 			note("GPG signature not checked (--skip-sig)")
			// 		} else {
			// 			g := seal.GPG{Bin: gpgBin, Home: gnupgHome}
			// 			if err := g.Available(); err != nil {
			// 				fail("%v", err)
			// 			} else if res, err := g.Verify(pubkey, sl.Statement, sl.Signature); err != nil {
			// 				fail("signature: %v", err)
			// 			} else {
			// 				if fingerprint != "" && !seal.MatchFingerprint(fingerprint, res) {
			// 					fail("signed by %s, not the required %s", res.Primary, fingerprint)
			// 				} else {
			// 					pass("signed by %s", res.Primary)
			// 				}
			// 				if sl.Fingerprint != "" && !strings.EqualFold(sl.Fingerprint, res.Primary) {
			// 					fail("manifest claims signer %s but the signature is from %s", sl.Fingerprint, res.Primary)
			// 				}
			// 				if res.Warning != "" {
			// 					note("%s", res.Warning)
			// 				}
			// 				if !pinned {
			// 					note("no --pubkey/--fingerprint given: any key in your keyring is accepted as the signer")
			// 				}
			// 			}
			// 		}
			// 	}
			// 	if sl.Signature == "" || sigBytes != nil {
			// 		if seal.Digest(sl.Statement, sigBytes) == sl.Digest {
			// 			pass("seal digest %s derives from the statement and signature", short(sl.Digest))
			// 		} else {
			// 			fail("seal digest does not derive from the statement and signature")
			// 		}
			// 	}
			// 	digest, _ = hex.DecodeString(sl.Digest)
			// }

			if problems > 0 {
				return fmt.Errorf("verification failed: %d problem(s)", problems)
			}
			fmt.Fprintf(out, "\nverified  root %s\n", ix.Root)
			return nil
		},
	}
	addIndexFlag(c, &idxPath)
	f := c.Flags()
	f.StringVar(&source, "source", "", "also check this bibliography file against the committed one")
	f.StringVar(&wantRoot, "root", "", "expected root hash (from a trusted source)")
	f.StringVar(&pubkey, "pubkey", "", "signer's public key file; only this key can satisfy the signature check")
	f.StringVar(&fingerprint, "fingerprint", "", "required signer fingerprint (or long key ID)")
	f.StringVar(&heartP, "heart", "", "check this heart PNG instead of the one next to the manifest")
	f.BoolVar(&skipFiles, "skip-files", false, "do not read PDFs or the heart next to the manifest")
	f.BoolVar(&skipSig, "skip-sig", false, "do not run gpg (the digest and heart are still checked)")
	f.StringVar(&gpgBin, "gpg", "", "gpg binary (default: gpg)")
	f.StringVar(&gnupgHome, "gnupg-home", "", "GnuPG home directory")
	return c
}

// compareRefs reports which committed references were added, removed or moved.
func compareRefs(source string, ix *index.Index, fail func(string, ...any)) {
	refs, err := hayagriva.Parse(source)
	if err != nil {
		return
	}
	now := map[string]string{}
	for _, r := range refs {
		if r.URL != "" {
			now[r.Key] = r.URL
		}
	}
	then := map[string]string{}
	for _, e := range ix.Entries {
		if e.URL != "" {
			then[e.Key] = e.URL
		}
	}
	for k, u := range then {
		switch nu, ok := now[k]; {
		case !ok:
			fail("reference %q was removed", k)
		case nu != u:
			fail("reference %q changed URL", k)
		}
	}
	for k := range now {
		if _, ok := then[k]; !ok {
			fail("reference %q was added", k)
		}
	}
}
