package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"veribib/internal/hayagriva"
	"veribib/internal/index"
	"veribib/internal/merkle"
	"veribib/internal/pdf"
)

type buildOpts struct {
	out           string
	chrome        string
	jobs          int
	timeout       time.Duration
	budget        time.Duration
	noSandbox     bool
	noPreflight   bool
	reuse         bool
	keepGoing     bool
	allowEmptyUrl bool
	sign          signOpts
}

func newBuildCmd() *cobra.Command {
	var o buildOpts
	c := &cobra.Command{
		Use:   "build <bibliography.yaml>",
		Short: "Archive every reference as a PDF, build the tree, sign the root, mint the heart",
		Long: `Scans the bibliography, prints each URL to PDF with headless Chrome, hashes the
PDFs, builds the Merkle tree, signs the root with GPG and writes:

  <out>/index.json   the manifest: every hash, the signed seal, per-entry metadata
  <out>/pdfs/*.pdf   the archived pages
  <out>/heart.png    the seal digest as a pixel heart

Ship index.json and heart.png together. Chrome embeds a creation timestamp in
its PDFs, so re-rendering a page gives a different hash; the archived PDFs are
the evidence. Use --reuse to re-commit to PDFs already on disk.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var bibfile = "bibliography.yml"
			if len(args) > 0 {
				bibfile = args[0]
			}

			return runBuild(cmd, bibfile, &o)
		},
	}
	f := c.Flags()
	f.StringVarP(&o.out, "out", "o", "veribib-out", "output directory")
	f.StringVar(&o.chrome, "chrome", "", "Chrome/Chromium binary (default: search $PATH, or $veribib_CHROME)")
	f.IntVarP(&o.jobs, "jobs", "j", 4, "pages to render in parallel")
	f.DurationVar(&o.timeout, "timeout", 90*time.Second, "per-page browser timeout")
	f.DurationVar(&o.budget, "virtual-time-budget", 10*time.Second, "how long pages may keep loading before printing")
	f.BoolVar(&o.noSandbox, "no-sandbox", false, "pass --no-sandbox to Chrome (needed as root / in containers)")
	f.BoolVar(&o.noPreflight, "no-preflight", false, "skip the HTTP status check before rendering")
	f.BoolVar(&o.reuse, "reuse", false, "reuse PDFs already in <out>/pdfs instead of re-rendering")
	f.BoolVar(&o.keepGoing, "keep-going", false, "exclude references that fail instead of aborting")
	f.BoolVar(&o.allowEmptyUrl, "allow-empty-url", false, "Allow url field to be empty")
	o.sign.bind(c)
	return c
}

func runBuild(cmd *cobra.Command, bibPath string, o *buildOpts) error {
	logw := cmd.ErrOrStderr()
	// fail on bad flags or a missing gpg before spending time on the network
	if err := o.sign.validate(); err != nil {
		return err
	}

	refs, err := hayagriva.Parse(bibPath)
	if err != nil {
		return err
	}

	srcSum, srcSize, err := sha256File(bibPath)
	if err != nil {
		return err
	}

	pdfDir := filepath.Join(o.out, "pdfs")
	if err := os.MkdirAll(pdfDir, 0o755); err != nil {
		return err
	}

	popts := pdf.Options{Timeout: o.timeout, VirtualTimeBudget: o.budget, NoSandbox: o.noSandbox}
	renderer := ""
	for _, r := range refs {
		if r.URL == "" {
			continue
		}

		chrome, err := pdf.FindChrome(o.chrome)
		if err != nil {
			return err
		}

		popts.Chrome = chrome
		renderer = pdf.Version(chrome)
		break
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	entries := make([]index.Entry, len(refs))
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	logf := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(logw, format, a...)
	}
	sem := make(chan struct{}, max(o.jobs, 1))

	for i, ref := range refs {
		e := index.Entry{Key: ref.Key, Type: ref.Type, Title: ref.Title, URL: ref.URL}
		if ref.URL == "" && !o.allowEmptyUrl {
			e.Status = index.StatusSkipped
			e.Error = "no url"
			entries[i] = e
			logf("skip  %s (no url)\n", ref.Key)
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(i int, e index.Entry) {
			defer func() { <-sem; wg.Done() }()
			e = archive(ctx, popts, o, pdfDir, e)
			entries[i] = e
			if e.Status == index.StatusOK {
				logf("ok    %s  %s\n", e.Key, short(e.PDFSHA256))
			} else {
				logf("FAIL  %s  %s\n", e.Key, e.Error)
			}
		}(i, e)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	var failed []string
	for _, e := range entries {
		if e.Status == index.StatusFailed {
			failed = append(failed, fmt.Sprintf("  %s: %s", e.Key, e.Error))
		}
	}

	if len(failed) > 0 && !o.keepGoing {
		return fmt.Errorf("%d reference(s) failed (rerun with --keep-going to exclude them):\n%s",
			len(failed), strings.Join(failed, "\n"))
	}

	var leaves []merkle.Hash
	for i := range entries {
		e := &entries[i]
		if e.Status != index.StatusOK {
			continue
		}

		h, err := merkle.ParseHash(e.LeafHash)
		if err != nil {
			return err
		}

		pos := len(leaves)
		e.LeafIndex = &pos
		leaves = append(leaves, h)
	}

	tree, err := merkle.Build(leaves)
	if err != nil {
		return fmt.Errorf("nothing to commit: %w", err)
	}

	ix := &index.Index{
		Version:   index.FormatVersion,
		Tool:      "veribib " + Version,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Renderer:  renderer,
		Source:    index.Source{File: bibPath, SHA256: srcSum, Size: srcSize},
		Tree:      index.DefaultTreeSpec(),
		Root:      tree.Root().String(),
		LeafCount: len(leaves),
		Levels:    tree.Strings(),
		Entries:   entries,
	}

	// signing layer first, then the heart is rendered from the signature
	if err := mintSeal(ix, &o.sign); err != nil {
		return err
	}

	indexFile := filepath.Join(o.out, "index.json")
	if err := ix.Save(indexFile); err != nil {
		return err
	}

	printSeal(cmd, ix, indexFile)
	fmt.Fprintf(cmd.OutOrStdout(), "leaves  %d committed, %d excluded\n", len(leaves), len(refs)-len(leaves))
	return nil
}

// archive renders one reference and fills in its hashes.
func archive(ctx context.Context, po pdf.Options, o *buildOpts, pdfDir string, e index.Entry) index.Entry {
	name := fileName(e.Key)
	dest := filepath.Join(pdfDir, name)
	e.PDF = path.Join("pdfs", name)
	fail := func(err error) index.Entry {
		e.Status = index.StatusFailed
		e.Error = err.Error()
		e.PDF = ""
		return e
	}

	var fetched time.Time
	if st, err := os.Stat(dest); o.reuse && err == nil {
		fetched = st.ModTime().UTC().Truncate(time.Second)
	} else {
		if !o.noPreflight {
			status, final, err := pdf.Preflight(ctx, e.URL)
			e.HTTPStatus = status
			if final != "" && final != e.URL {
				e.FinalURL = final
			}

			if err != nil {
				return fail(err)
			}
		}

		if err := pdf.Export(ctx, po, e.URL, dest); err != nil {
			return fail(err)
		}

		fetched = time.Now().UTC().Truncate(time.Second)
	}

	sum, size, err := sha256File(dest)
	if err != nil {
		return fail(err)
	}

	e.Status = index.StatusOK
	e.PDFSHA256 = sum
	e.PDFSize = size
	e.FetchedAt = &fetched
	leaf, err := e.LeafHashOf()
	if err != nil {
		return fail(err)
	}

	e.LeafHash = leaf.String()
	return e
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// fileName maps a citation key to a safe file name; keys that needed
// sanitising get a short hash suffix so distinct keys never collide.
func fileName(key string) string {
	safe := unsafeName.ReplaceAllString(key, "_")
	if safe != key || safe == "" || strings.HasPrefix(safe, ".") {
		sum := sha256.Sum256([]byte(key))
		safe = strings.TrimLeft(safe, ".") + "-" + hex.EncodeToString(sum[:4])
	}

	return safe + ".pdf"
}
