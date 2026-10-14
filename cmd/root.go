// Package cmd wires up the veribib command line.
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/spf13/cobra"

	"veribib/internal/index"
)

const (
	Version      = "0.1.0"
	defaultIndex = "veribib-out/index.json"
)

func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return newRoot().ExecuteContext(ctx)
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "veribib",
		Short: "Commit a Hayagriva bibliography to a Merkle root of archived PDFs",
		Long: `veribib archives every URL in a Hayagriva bibliography as a PDF, hashes each
PDF with SHA-256, and builds a Merkle tree over those hashes. The root hash
commits to the entire bibliography; per-reference inclusion proofs let anyone
check a single archived page without the rest.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newScanCmd(),
		newBuildCmd(),
		newSealCmd(),
		newVerifyCmd(),
		newProveCmd(),
		newCheckCmd(),
		newInfoCmd(),
		newLsCmd(),
		newTreeCmd(),
		newHashCmd(),
	)
	return root
}

func addIndexFlag(c *cobra.Command, p *string) {
	c.Flags().StringVarP(p, "index", "i", defaultIndex, "path to index.json")
}

func loadIndex(path string) (*index.Index, string, error) {
	ix, err := index.Load(path)
	if err != nil {
		return nil, "", err
	}

	return ix, filepath.Dir(path), nil
}

func sha256File(path string) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}

	defer f.Close()
	h := sha256.New()
	size, err = io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}

	return h
}
