package seal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GPG drives the gpg binary, so keys, agents, smartcards and pinentry all work
// as they do for the rest of your tooling.
type GPG struct {
	Bin            string // default "gpg"
	Home           string // --homedir (default: gpg's own, or $GNUPGHOME)
	PassphraseFile string // for non-interactive signing in CI (loopback pinentry)
}

func (g GPG) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "gpg"
}

// Available reports whether the gpg binary can be found.
func (g GPG) Available() error {
	if _, err := exec.LookPath(g.bin()); err != nil {
		return fmt.Errorf("gpg not found (%w); install GnuPG or pass --gpg", err)
	}
	return nil
}

func (g GPG) base(home string) []string {
	var a []string
	if home != "" {
		a = append(a, "--homedir", home)
	}
	return a
}

// Sign returns an ASCII-armored detached signature of data made by keyID.
func (g GPG) Sign(keyID, data string) (string, error) {
	args := g.base(g.Home)
	if g.PassphraseFile != "" {
		args = append(args, "--batch", "--pinentry-mode", "loopback", "--passphrase-file", g.PassphraseFile)
	}
	args = append(args, "--armor", "--detach-sign", "--local-user", keyID)
	cmd := exec.Command(g.bin(), args...)
	cmd.Stdin = strings.NewReader(data)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gpg sign failed: %w: %s", err, lastLine(errb.String()))
	}
	return out.String(), nil
}

// Result describes a verified signature.
type Result struct {
	Primary    string // fingerprint of the signer's primary key
	SigningKey string // fingerprint of the (sub)key that made the signature
	Warning    string // e.g. the key has since expired
}

// Verify checks armoredSig over data. If pubkeyFile is set the key is imported
// into a throwaway keyring, so only that key can satisfy the check; otherwise
// the normal keyring is used.
func (g GPG) Verify(pubkeyFile, data, armoredSig string) (*Result, error) {
	home := g.Home
	if pubkeyFile != "" {
		tmp, err := os.MkdirTemp("", "bibroot-gnupg-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		if err := os.Chmod(tmp, 0o700); err != nil {
			return nil, err
		}
		defer func() { // stop any agent gpg started for the throwaway home
			_ = exec.Command("gpgconf", "--homedir", tmp, "--kill", "all").Run()
		}()
		imp := exec.Command(g.bin(), append(g.base(tmp), "--batch", "--import", pubkeyFile)...)
		var ie bytes.Buffer
		imp.Stderr = &ie
		if err := imp.Run(); err != nil {
			return nil, fmt.Errorf("cannot import %s: %w: %s", pubkeyFile, err, lastLine(ie.String()))
		}
		home = tmp
	}

	work, err := os.MkdirTemp("", "bibroot-verify-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	sigPath, dataPath := filepath.Join(work, "seal.asc"), filepath.Join(work, "statement.txt")
	if err := os.WriteFile(sigPath, []byte(armoredSig), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		return nil, err
	}

	cmd := exec.Command(g.bin(), append(g.base(home), "--status-fd=1", "--verify", sigPath, dataPath)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()

	var good, expired, revoked, bad, noKey bool
	res := &Result{}
	for _, line := range strings.Split(out.String(), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "[GNUPG:] ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "GOODSIG":
			good = true
		case "EXPKEYSIG":
			expired = true
		case "REVKEYSIG":
			revoked = true
		case "BADSIG":
			bad = true
		case "NO_PUBKEY":
			noKey = true
		case "VALIDSIG":
			if len(f) >= 2 {
				res.SigningKey, res.Primary = f[1], f[1]
			}
			if len(f) >= 11 {
				res.Primary = f[10]
			}
		}
	}
	switch {
	case bad:
		return nil, errors.New("BAD signature: the statement or signature was altered")
	case revoked:
		return nil, errors.New("the signing key has been revoked")
	case noKey && pubkeyFile != "":
		return nil, fmt.Errorf("signature was not made by the key in %s", pubkeyFile)
	case noKey:
		return nil, errors.New("signer's public key is not in the keyring; pass --pubkey FILE")
	case !(good || expired) || res.Primary == "":
		return nil, fmt.Errorf("signature not valid: %v: %s", runErr, lastLine(errb.String()))
	}
	if expired {
		res.Warning = "signing key has expired since this was signed"
	}
	return res, nil
}

// MatchFingerprint reports whether pin (a full fingerprint or a long key ID
// of at least 16 hex digits) identifies the signer.
func MatchFingerprint(pin string, r *Result) bool {
	p := strings.ToUpper(strings.NewReplacer(" ", "", "0X", "", "0x", "").Replace(pin))
	if len(p) < 16 {
		return false
	}
	return strings.HasSuffix(strings.ToUpper(r.Primary), p) || strings.HasSuffix(strings.ToUpper(r.SigningKey), p)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
