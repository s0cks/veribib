package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"veribib/internal/index"
	"veribib/internal/seal"
)

// signOpts are the flags for the GPG signing layer.
type signOpts struct {
	key, gpgBin, gnupgHome, passFile string
	unsigned                         bool
}

func (s *signOpts) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&s.key, "sign", os.Getenv("veribib_SIGN_KEY"), "GPG key (id, fingerprint or email) that signs the seal [$BIBROOT_SIGN_KEY]")
	f.BoolVar(&s.unsigned, "unsigned", false, "mint the heart without a GPG signature")
	f.StringVar(&s.gpgBin, "gpg", "", "gpg binary (default: gpg)")
	f.StringVar(&s.gnupgHome, "gnupg-home", "", "GnuPG home directory (default: $GNUPGHOME or ~/.gnupg)")
	f.StringVar(&s.passFile, "gpg-passphrase-file", "", "read the key passphrase from this file (non-interactive CI signing)")
	c.MarkFlagsMutuallyExclusive("sign", "unsigned")
}

func (s *signOpts) gpg() seal.GPG {
	return seal.GPG{Bin: s.gpgBin, Home: s.gnupgHome, PassphraseFile: s.passFile}
}

func (s *signOpts) validate() error {
	if s.unsigned {
		return nil
	}
	if s.key == "" {
		return errors.New("signing is required: pass --sign KEY (or set $veribib_SIGN_KEY), or --unsigned to skip the signature")
	}
	return s.gpg().Available()
}

// mintSeal signs the root statement and derives the digest the heart shows.
func mintSeal(ix *index.Index, s *signOpts) error {
	stmt := seal.Statement(ix.Root, ix.Source.SHA256, ix.LeafCount, ix.CreatedAt)
	sl := &index.Seal{Statement: stmt}
	var sig []byte
	if !s.unsigned {
		g := s.gpg()
		armored, err := g.Sign(s.key, stmt)
		if err != nil {
			return err
		}
		// Self-check: proves the signature is valid and tells us which primary
		// key (not just which subkey) made it.
		res, err := g.Verify("", stmt, armored)
		if err != nil {
			return fmt.Errorf("self-check of the new signature failed: %w", err)
		}
		if sig, err = seal.Dearmor(armored); err != nil {
			return err
		}
		sl.Signature, sl.Fingerprint = armored, res.Primary
	}
	sl.Digest = seal.Digest(stmt, sig)
	ix.Seal = sl
	return nil
}

func newSealCmd() *cobra.Command {
	var (
		idxPath string
		s       signOpts
	)
	c := &cobra.Command{
		Use:   "seal",
		Short: "(Re)sign an existing manifest and re-mint its heart",
		Long: `Signs the manifest's root statement with GPG and renders the heart from the
signature. "build" does this in one go; use "seal" to sign separately (say, on
a machine that holds the key) or to re-sign with a different key. A fresh
signature gives a new heart.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := s.validate(); err != nil {
				return err
			}
			ix, _, err := loadIndex(idxPath)
			if err != nil {
				return err
			}
			tree, err := ix.Rebuild()
			if err != nil {
				return err
			}
			if tree.Root().String() != ix.Root {
				return errors.New("manifest is inconsistent (rebuilt root differs from recorded root); run `veribib verify`")
			}
			if err := mintSeal(ix, &s); err != nil {
				return err
			}
			if err := ix.Save(idxPath); err != nil {
				return err
			}
			printSeal(cmd, ix, idxPath)
			return nil
		},
	}
	addIndexFlag(c, &idxPath)
	s.bind(c)
	return c
}

func printSeal(cmd *cobra.Command, ix *index.Index, indexFile string) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "root    %s\n", ix.Root)
	if ix.Seal != nil {
		if ix.Seal.Fingerprint != "" {
			fmt.Fprintf(out, "signer  %s\n", ix.Seal.Fingerprint)
		} else {
			fmt.Fprintln(out, "signer  (unsigned)")
		}
		fmt.Fprintf(out, "seal    %s\n", ix.Seal.Digest)
	}
	fmt.Fprintf(out, "index   %s\n", indexFile)
}
