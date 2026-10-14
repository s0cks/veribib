package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"veribib/internal/index"
)

func newInfoCmd() *cobra.Command {
	var idxPath string
	c := &cobra.Command{
		Use:   "info",
		Short: "Summarise an index: root, counts, source, renderer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ix, _, err := loadIndex(idxPath)
			if err != nil {
				return err
			}
			counts := map[string]int{}
			for _, e := range ix.Entries {
				counts[e.Status]++
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			row := func(k, format string, a ...any) { fmt.Fprintf(tw, "%s\t"+format+"\n", append([]any{k}, a...)...) }
			row("root", "%s", ix.Root)
			if ix.Seal != nil {
				signer := "unsigned"
				if ix.Seal.Fingerprint != "" {
					signer = "signed by " + ix.Seal.Fingerprint
				}
				row("seal", "%s (%s)", ix.Seal.Digest, signer)
			}
			row("leaves", "%d (tree height %d)", ix.LeafCount, len(ix.Levels)-1)
			row("entries", "%d ok, %d failed, %d skipped", counts[index.StatusOK], counts[index.StatusFailed], counts[index.StatusSkipped])
			row("created", "%s", ix.CreatedAt.Format(time.RFC3339))
			row("source", "%s (sha256 %s, %d bytes)", ix.Source.File, short(ix.Source.SHA256), ix.Source.Size)
			row("tool", "%s", ix.Tool)
			if ix.Renderer != "" {
				row("renderer", "%s", ix.Renderer)
			}
			row("leaf record", "%s", ix.Tree.Record)
			row("leaf hash", "%s", ix.Tree.Leaf)
			row("node hash", "%s", ix.Tree.Node)
			return tw.Flush()
		},
	}
	addIndexFlag(c, &idxPath)
	return c
}

func newLsCmd() *cobra.Command {
	var idxPath string
	var full bool
	c := &cobra.Command{
		Use:   "ls",
		Short: "List index entries with their hashes and fetch times",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ix, _, err := loadIndex(idxPath)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "LEAF\tKEY\tSTATUS\tPDF SHA-256\tSIZE\tFETCHED\tURL")
			for _, e := range ix.Entries {
				leaf, sum, size, at := "-", "-", "-", "-"
				if e.LeafIndex != nil {
					leaf = fmt.Sprint(*e.LeafIndex)
				}
				if e.PDFSHA256 != "" {
					sum = e.PDFSHA256
					if !full {
						sum = short(sum)
					}
					size = fmt.Sprint(e.PDFSize)
				}
				if e.FetchedAt != nil {
					at = e.FetchedAt.Format(time.RFC3339)
				}
				status := e.Status
				if e.Error != "" {
					status += " (" + e.Error + ")"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", leaf, e.Key, status, sum, size, at, e.URL)
			}
			return tw.Flush()
		},
	}
	addIndexFlag(c, &idxPath)
	c.Flags().BoolVar(&full, "full", false, "show full hashes")
	return c
}

func newTreeCmd() *cobra.Command {
	var idxPath string
	var full bool
	c := &cobra.Command{
		Use:   "tree",
		Short: "Print the Merkle tree",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ix, _, err := loadIndex(idxPath)
			if err != nil {
				return err
			}

			var names []string
			for _, e := range ix.Entries {
				if e.Status == index.StatusOK {
					names = append(names, e.Key)
				}
			}

			if len(ix.Levels) == 0 || len(ix.Levels[0]) != len(names) {
				return fmt.Errorf("index levels do not match its entries; run `veribib verify`")
			}

			top := len(ix.Levels) - 1
			walk(cmd.OutOrStdout(), ix.Levels, names, full, top, 0, "", true, true)
			return nil
		},
	}
	addIndexFlag(c, &idxPath)
	c.Flags().BoolVar(&full, "full", false, "show full hashes")
	return c
}

// walk prints the subtree rooted at (lvl, idx). A node with a single child is
// a promoted odd node and is printed once, at leaf level or where it is real.
func walk(w io.Writer, lv [][]string, names []string, full bool, lvl, idx int, prefix string, last, isRoot bool) {
	for lvl > 0 && 2*idx+1 >= len(lv[lvl-1]) {
		lvl, idx = lvl-1, 2*idx
	}

	connector, childPrefix := "├── ", prefix+"│   "
	if last {
		connector, childPrefix = "└── ", prefix+"    "
	}

	if isRoot {
		connector, childPrefix = "", ""
	}

	label := lv[lvl][idx]
	if !full {
		label = short(label)
	}

	if lvl == 0 {
		label += "  " + names[idx]
	}

	fmt.Fprintf(w, "%s%s%s\n", prefix, connector, label)
	if lvl == 0 {
		return
	}

	walk(w, lv, names, full, lvl-1, 2*idx, childPrefix, false, false)
	walk(w, lv, names, full, lvl-1, 2*idx+1, childPrefix, true, false)
}

func newHashCmd() *cobra.Command {
	var idxPath string
	c := &cobra.Command{
		Use:   "hash <file>...",
		Short: "Print the SHA-256 of files, and which manifest entry (if any) they are",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ix, _, _ := loadIndex(idxPath) // optional
			out := cmd.OutOrStdout()
			for _, f := range args {
				sum, _, err := sha256File(f)
				if err != nil {
					return err
				}

				fmt.Fprintf(out, "%s\n  sha256  %s\n", f, sum)
				if ix == nil {
					continue
				}

				found := false
				for _, e := range ix.Entries {
					if e.Status == index.StatusOK && e.PDFSHA256 == sum {
						fmt.Fprintf(out, "  index   %s (leaf %d, leaf hash %s)\n", e.Key, *e.LeafIndex, e.LeafHash)
						found = true
					}
				}

				if !found {
					fmt.Fprintln(out, "  index   not in the manifest")
				}
			}

			return nil
		},
	}

	c.Flags().StringVarP(&idxPath, "index", "i", defaultIndex, "manifest to look the hash up in (optional)")
	return c
}
