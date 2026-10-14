# bibroot

Archive a [Hayagriva](https://github.com/typst/hayagriva) bibliography, commit to it with a Merkle root,
sign the root with GPG, and mint a pixel-art heart from the signature. Ship `heart.png` + `index.json`.

```
refs.yaml ─▶ URLs ─▶ PDFs ─▶ records ─▶ Merkle root ─▶ GPG-signed seal ─▶ ♥ heart.png
                                                              └────────▶ index.json (manifest)
```

## Setup

```sh
go mod tidy && go build -o bibroot .
```

Needs Chrome/Chromium (`--chrome`, `$BIBROOT_CHROME`; add `--no-sandbox` as root/in Docker) and `gpg`.

## Publishing workflow

```sh
# build step: cache URLs as PDFs, build the tree, sign, mint the heart
bibroot build refs.yaml -o site/provenance --sign <YOUR-KEY-FPR>

# embed site/provenance/heart.png in the page; publish index.json next to it
# (keep pdfs/ wherever you archive evidence; it does not need to be public)

# anyone can check the published pair
bibroot verify -i index.json --pubkey you.asc --fingerprint <YOUR-KEY-FPR> --heart embedded-copy.png
bibroot heart --decode embedded-copy.png     # prints the 256-bit seal digest
```

`--sign` also reads `$BIBROOT_SIGN_KEY`. For unattended CI use a dedicated signing key and
`--gpg-passphrase-file` (GnuPG loopback pinentry), or preset the passphrase in gpg-agent.
`bibroot seal` signs an existing manifest separately, e.g. on the machine that holds the key.

## Commands

| | |
|---|---|
| `scan` | list references and the URLs that would be archived |
| `build` | archive, hash, build tree, sign, render heart, write manifest |
| `seal` | (re)sign an existing manifest and re-mint its heart |
| `verify` | re-hash PDFs, rebuild tree, check the GPG seal and the heart |
| `prove <key>` | inclusion proof for one reference (carries the signed seal) |
| `check` | verify a proof / a PDF against the seal |
| `info` `ls` `tree` `hash` | introspection |
| `heart` | render a digest, or `--decode` one out of a PNG |

## What is committed to what

| layer | contents |
|---|---|
| record | `bibroot-leaf-v1` text: citation key, URL, fetch time, sha256(pdf) |
| leaf | `sha256(0x00 ‖ record)` |
| node | `sha256(0x01 ‖ left ‖ right)`; odd node promoted unchanged; leaves ordered by key |
| statement | root, sha256 of the source YAML, leaf count, creation time |
| signature | OpenPGP detached signature over the statement (made by your `gpg`) |
| **heart digest** | `sha256("bibroot-heart-v1" ‖ 0 ‖ statement ‖ 0 ‖ signature)` |

Relabelling an entry, changing a URL or fetch time, swapping a PDF, editing the YAML, or re-rolling
the tree changes the root and breaks the signature. The heart depends on the signature, so a heart
cannot be minted for a manifest without the private key. Fields such as `title`, `type`,
`http_status` and `final_url` are informational and are not signed.

## The heart

Cells inside the heart silhouette carry the digest's bits, MSB-first, in reading order:
`1` = red, `0` = transparent; cells outside the silhouette are transparent too, so it shows as red
speckle. The grid auto-sizes to the smallest one with at least 256 cells; extra cells repeat the
bits from the start. On a dark background it reads as a heart; `bibroot heart` (no `-o`) prints a
terminal view that also marks the `0` cells. Nearest-neighbour resizes of the PNG (whole multiples
of the grid size) still decode and verify.

## Trust model

- A manifest on its own only proves it is self-consistent. Trust comes from the key: pass
  `--pubkey`/`--fingerprint` to `verify`/`check`, otherwise *any* key in your keyring that signed
  it is accepted (and reported).
- The heart PNG is a token, not a proof: anyone can copy it. It means something because
  `verify --heart` (or `heart --decode`) ties it back to the signed manifest.
- The signature carries GnuPG's signing time but there is no independent timestamp. If you need
  one, add an RFC 3161 / OpenTimestamps step over the digest.
- Chrome PDFs embed a creation date, so re-rendering gives new hashes; the archived PDFs are the
  evidence. `build --reuse` re-commits to PDFs already on disk.
- Dead links: Chrome prints its own error page to PDF with exit 0, so `build` does an HTTP
  preflight first (`--no-preflight` to skip). Failed references abort unless `--keep-going`.
- Entries with no `url` (own or on a `parent`) are listed as `skipped` and are not in the tree.

## Manifest layout

`version`, `tool`, `created_at`, `renderer`, `source` (file + sha256), `tree` (hash spec), `root`,
`leaf_count`, `levels` (every hash; `levels[0]` are the leaves), `seal` (`statement`, `signature`,
`fingerprint`, `digest`), `heart` (file, grid, scale, color), and `entries` (`key`, `url`, `status`,
`leaf_index`, `pdf`, `pdf_size`, `pdf_sha256`, `leaf_hash`, `fetched_at`, ...).
