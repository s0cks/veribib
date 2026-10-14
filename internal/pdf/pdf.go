// Package pdf exports web pages to PDF by driving a headless Chrome/Chromium.
package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Options configures the exporter.
type Options struct {
	Chrome            string        // path to the browser binary
	Timeout           time.Duration // per-page limit
	VirtualTimeBudget time.Duration // how long the page may keep loading scripts/assets
	NoSandbox         bool          // needed when running as root / in containers
}

// FindChrome resolves the browser binary: explicit flag, $BIBROOT_CHROME, then
// well-known names.
func FindChrome(explicit string) (string, error) {
	if explicit != "" {
		return exec.LookPath(explicit)
	}

	if env := os.Getenv("BIBROOT_CHROME"); env != "" {
		return exec.LookPath(env)
	}

	for _, c := range []string{
		"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "microsoft-edge",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}

	return "", errors.New("no Chrome/Chromium found: install one, set $BIBROOT_CHROME, or pass --chrome")
}

// Version returns the browser's --version string (empty on failure).
func Version(chrome string) string {
	out, err := exec.Command(chrome, "--version").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

// Preflight does a plain GET so that dead links fail loudly. Chrome happily
// prints its own "site can't be reached" error page to PDF with exit code 0,
// which would otherwise get hashed into the tree as if it were the reference.
func Preflight(ctx context.Context, rawURL string) (status int, finalURL string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
	// req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; bibroot)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}

	defer resp.Body.Close()
	finalURL = resp.Request.URL.String()
	if resp.StatusCode >= 400 {
		return resp.StatusCode, finalURL, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return resp.StatusCode, finalURL, nil
}

// Export prints rawURL to a PDF at dest.
func Export(ctx context.Context, opts Options, rawURL, dest string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("unsupported URL %q (need http or https)", rawURL)
	}

	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	profile, err := os.MkdirTemp("", "bibroot-chrome-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(profile)

	tmp := abs + ".part"
	defer os.Remove(tmp)

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--hide-scrollbars",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-blink-features=AutomationControlled",
		"--disable-javascript",
		// "--blink-settings=scriptEnabled=false",
		"--no-pdf-header-footer",
		"--user-data-dir=" + profile,
		"--print-to-pdf=" + tmp,
		fmt.Sprintf("--virtual-time-budget=%d", opts.VirtualTimeBudget.Milliseconds()),
	}

	if opts.NoSandbox {
		args = append(args, "--no-sandbox")
	}

	args = append(args, u.String())

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, opts.Chrome, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("browser timed out after %s", opts.Timeout)
		}

		return fmt.Errorf("browser failed: %w: %s", err, lastLine(stderr.String()))
	}

	f, err := os.Open(tmp)
	if err != nil {
		return fmt.Errorf("browser produced no output: %w", err)
	}

	magic := make([]byte, 5)
	_, rerr := f.Read(magic)
	f.Close()
	if rerr != nil || string(magic) != "%PDF-" {
		return errors.New("browser output is not a PDF")
	}

	return os.Rename(tmp, abs)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
