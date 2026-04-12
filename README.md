# Giant Cipher Solver

Automated cryptanalysis CLI for **Call of Duty: Black Ops III — Zombies**–style **Base64 ciphertext** (including **The Giant** community hunts). It scores thousands of transform outputs with English heuristics, runs **time-bounded brute force** on repeating XOR and Base64-alphabet Vigenère/Beaufort, and adds **extended probes** (classical ciphers, OpenSSL block decrypts, layered decoding).

This tool **searches and ranks** candidates. It does **not** guarantee a plaintext for unsolved or arbitrarily layered real-world ciphers.

---

## Features

| Area | What it does |
|------|----------------|
| **Heuristics** | Lore/Treyarch keyword lists, single-byte XOR on decoded bytes, Base64 alphabet rotation, Atbash on Base64, Vigenère/Beaufort on the outer Base64 string, reversed ciphertext, XOR on the Base64 ASCII string |
| **Extended probes** | Beaufort/Vigenère on **A–Z** and **A–Za–z** (52-char “Revelations-style” alphabet), Atbash, Caesar shifts, ROT13, rail-fence, cumulative-XOR unroll, **OpenSSL** tries (AES/3DES/RC2/Blowfish when available), ciphertext byte-reversal before decrypt |
| **Layered search** | Nested Base64, zlib/gzip/inflate, hex-as-ASCII, nibble swap, repeating XOR, RC4, optional 256 single-byte XOR per layer buffer |
| **Auto solve** | After heuristics, parallel brute XOR (`[a-zA-Z0-9]^1…L`) then Vigenère + Beaufort on Base64 (`L` configurable), until strict English or time limit |
| **Analysis UI** | Payload fingerprint (entropy, magic bytes, nested-format hints), **hex pattern scan** (annotated dump, XOR key hints, structural notes), analytics dashboard, dictionary token scan, session log |
| **Live progress** | TTY-only yellow **live brute** panel: pipeline bar, keys tried/left, phase budget countdown, ETA (during XOR/Vigenère phases) |

---

## Requirements

- **Node.js** ≥ 18 (`node -v`)
- **npm** (ships with Node)

---

## Quick start

```bash
git clone <your-repo-url>
cd GiantCipher
npm install
npm run solve
```

Put your Base64 in `cipherbase.json`:

```json
{
  "cipher": "PASTE_BASE64_CIPHERTEXT_HERE"
}
```

Optional extra field `mainkey` is ignored by the solver today; only `cipher` is required.

Use another file:

```bash
npm run build
node dist/index.js --file path/to/cipher.json
```

---

## npm scripts

Scripts use **`cross-env`** so the same commands work on Windows, macOS, and Linux.

| Script | Purpose |
|--------|---------|
| `npm run build` | Compile TypeScript → `dist/` |
| `npm run solve` / `npm start` | **Default “max heuristic”** preset: wide extended keywords, deep nested Base64, large layer buffers, full XOR/RC4 key lists (see `package.json` for exact `GIANT_*` values). Uses app defaults for brute **XOR length 4**, **Vig length 3**, **10 min** wall time unless you override env. |
| `npm run solve:quick` | Fast iteration: **2/2** brute lengths, **3 min** budget, smaller extended + layer caps |
| `npm run solve:full` | **4/4** brute lengths, **10 min** budget, same large extended + layer preset as `solve` |
| `npm run solve:30m` … `solve:24h` | **5/5** brute lengths, time budget in the name, full extended preset, tuned `GIANT_PROGRESS_EVERY` for long runs |
| `npm run solve:unlimited` | **No wall time** on brute phases (`GIANT_MAX_MS=0`); stop with **Ctrl+C** (interrupt handler prints last progress) |
| `npm run dump` | `--dump-all`: list scored candidates **without** the automatic brute loop (good for inspecting the heuristic pool) |
| `npm run help` | CLI usage and environment variables |

Worker threads default to **CPU logical core count**. To cap or raise (e.g. 24), set `GIANT_THREADS` before running.

---

## Command-line options

```
node dist/index.js [options]

  -f, --file <path>   JSON with { "cipher": "<base64>" } (default: cipherbase.json)
  --dump-all          Legacy: all scored candidates (no auto brute loop)
  --min-score <n>     With --dump-all: minimum heuristic score
  -n, --limit <n>     With --dump-all: max rows
  --jsonl             With --dump-all: one JSON object per line
  -h, --help          Show help
```

---

## Environment variables

### Brute phases (auto solve)

| Variable | Meaning |
|----------|---------|
| `GIANT_MAX_MS` | Wall time for **XOR + Vigenère/Beaufort brute only** (ms). Default `600000` (10 min). `0` = unlimited. |
| `GIANT_BRUTE_XOR_LEN` | Max repeating XOR key length over `[a-zA-Z0-9]`. Default `4`. Warns if `>3`. |
| `GIANT_BRUTE_VIG_LEN` | Max Vigenère + Beaufort key length on the **Base64 string** (same alphabet). Default `3`. Warns if `>3`. |
| `GIANT_PROGRESS_EVERY` | Log XOR brute progress every N tries (`0` = off). |
| `GIANT_THREADS` | Worker threads for large ranges (default: CPU count; `1` = single-threaded). |
| `GIANT_EXTRA_KEYS` | Comma/semicolon-separated extra keys for heuristics (XOR, Vigenère, layered RC4, etc.). |

### Extended probes (heuristic pool)

| Variable | Meaning |
|----------|---------|
| `GIANT_EXTENDED_PROBES` | `0` = skip classical + block-cipher + cumulative-XOR probes. Default on. |
| `GIANT_CLASSICAL_PROBES` | `0` = skip classical letter ciphers. |
| `GIANT_BLOCK_CIPHER_PROBES` | `0` = skip OpenSSL block decrypt attempts. |
| `GIANT_EXTENDED_KEYWORDS` | Max size of merged keyword list (default `120` in code; npm `solve` uses `200`). |
| `GIANT_CLASSICAL_KEYS` | Max keywords for classical ciphers only. |
| `GIANT_BLOCK_CIPHER_KEYS` | Max passphrases for block ciphers. |
| `GIANT_BLOCK_CIPHER_MAX` | Max successful block decrypts **per direction** (direct + reversed ciphertext). |

### Layered transforms

| Variable | Meaning |
|----------|---------|
| `GIANT_NESTED_B64` | Max nested Base64 unwrap depth |
| `GIANT_LAYER_MAX_BUFS` | Cap on distinct buffers in the layered pass |
| `GIANT_LAYER_XORREP` / `GIANT_LAYER_RC4` | How many stretched keys to use for layer XOR / RC4 |
| `GIANT_LAYER_XOR256` | Set `0` to skip 256 single-byte XOR on layer buffers |
| `GIANT_LAYER_XOR256_MAXBUFS` | How many layer buffers get the full single-byte XOR sweep |

### Logging

| Variable | Meaning |
|----------|---------|
| `GIANT_WORD_LOG` | Path for dictionary word-hit log (default `./giant-word-hits.log`) |

---

## What the run looks like

1. **Cryptanalysis running** — Keyspace estimates, thread count, time budget, note about the **live brute** panel (TTY only).
2. **Live brute panel** (TTY) — During XOR/Vigenère brute: progress bar, keys tried/left, budget countdown, ETA.
3. **Hero + input** — File path, Base64 length.
4. **Outer Base64** — Decoded payload fingerprint (entropy, hex preview, file signatures, nested-format hints).
5. **Hex pattern scan** — Annotated hex (first 128 bytes), byte stats, single-byte XOR printable hints, structural notes.
6. **Analytics dashboard** — Candidate pool stats, brute counts, transform mix.
7. **Execution pipeline** — Phases completed (heuristics, xor-brute, vig-brute, …).
8. **Dictionary token scan** — English tokens length ≥3.
9. **Word log path** — `giant-word-hits.log` (includes payload analysis append).
10. **Best candidate / readability** — If not strictly solved, near-miss and strict gate metrics.

Non-TTY (e.g. piped output): the live panel is skipped; sparse `⟳` lines may still appear if `GIANT_PROGRESS_EVERY` allows.

---

## Project layout

```
src/           TypeScript sources
dist/          Compiled output (after `npm run build`)
cipherbase.json   Default input JSON
giant-word-hits.log   Session log (overwritten each run, with append sections)
```

---

## Tips

- Start with `npm run solve:quick` to verify wiring; use `solve`, `solve:full`, or long scripts when you want maximum search breadth.
- **Payload / hex panels** are computed from the **decoded bytes** of `cipher` — they do not change between runs unless `cipher` changes.
- **Brute wall time** only applies to the **XOR + Vigenère/Beaufort** phases after heuristics; extended probes run in the earlier candidate generation pass (bounded by code and env).
- Add `GIANT_EXTRA_KEYS` for map-specific or community passphrase guesses without editing source.

---

## License

Add a `LICENSE` file in your repository if you publish this project; this README does not impose one by default.
