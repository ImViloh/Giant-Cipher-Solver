# Giant Cipher Solver

Automated cryptanalysis **CLI** for **Call of Duty: Black Ops III — Zombies**–style **Base64 ciphertext** (including **The Giant** community hunts). It scores thousands of transform outputs with English heuristics, runs **time-bounded brute force** on repeating XOR and Base64-alphabet Vigenère/Beaufort, and adds **extended probes** (classical ciphers, **COD-era classical** block, OpenSSL block decrypts, layered decoding).

This tool **searches and ranks** candidates. It does **not** guarantee a plaintext for unsolved or arbitrarily layered real-world ciphers.

---

## Features

| Area | What it does |
|------|----------------|
| **Heuristics** | Lore/Treyarch keyword lists, single-byte XOR on decoded bytes, Base64 alphabet rotation, Atbash on Base64, Vigenère/Beaufort on the outer Base64 string, reversed ciphertext, XOR on the Base64 ASCII string |
| **Extended probes** | Beaufort/Vigenère on **A–Z** and **A–Za–z** (52-char alphabet), Atbash, Caesar shifts, ROT13, rail-fence, cumulative-XOR unroll, **OpenSSL** tries (AES/3DES/RC2/Blowfish when available), ciphertext byte-reversal before decrypt |
| **COD-era classical** | Optional Affine (A26), Playfair, Bifid, columnar transposition, keyed Caesar, custom-alphabet (ZNS) Vigenère — gated by `GIANT_COD_*` env vars (see below) |
| **Layered search** | Nested Base64, zlib/gzip/inflate, hex-as-ASCII, nibble swap, repeating XOR, RC4, optional 256 single-byte XOR per layer buffer |
| **Auto solve** | After heuristics, parallel brute XOR (`[a-zA-Z0-9]^1…L`) then Vigenère + Beaufort on Base64 (`L` configurable), until strict English or time limit |
| **Analysis UI** | Payload fingerprint (entropy, magic bytes, nested-format hints), **hex pattern scan** (annotated dump, XOR key hints, structural notes), **cipher intelligence** panel, analytics dashboard, dictionary token scan, session log |
| **Cipher suite catalog** | Boxed terminal summary of method families (`codCipherSuite.ts`) — shown after runs and in `--dump-all` flows |
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

Put your Base64 in `cipherbase.json` (project root):

```json
{
  "cipher": "PASTE_BASE64_CIPHERTEXT_HERE"
}
```

Optional extra fields (e.g. `mainkey`) are ignored; only `cipher` is required.

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
| `npm run build` | Compile TypeScript → `dist/` (required before `node dist/index.js` if sources changed) |
| `npm run solve` / `npm start` | **Default “max heuristic”** preset: wide extended keywords, deep nested Base64, large layer buffers, full XOR/RC4 key lists (exact `GIANT_*` values are in `package.json`). App defaults for brute: **XOR length 4**, **Vig length 3**, **10 min** wall time unless overridden by env. |
| `npm run solve:quick` | Fast iteration: **2/2** brute lengths, **3 min** budget, smaller extended + layer caps |
| `npm run solve:full` | **4/4** brute lengths, **10 min** budget, same large extended + layer preset as `solve` |
| `npm run solve:30m` … `solve:24h` | **5/5** brute lengths, time budget in the name, full extended preset, tuned `GIANT_PROGRESS_EVERY` for long runs |
| `npm run solve:unlimited` | **No wall time** on brute phases (`GIANT_MAX_MS=0`); stop with **Ctrl+C** (interrupt handler prints last progress) |
| `npm run dump` | `--dump-all`: list scored candidates **without** the automatic brute loop (useful for inspecting the heuristic pool); also prints cipher-suite sections |
| `npm run help` | CLI usage and environment variables (`npm run build && node dist/index.js --help`) |
| `npm run cli` | Run compiled entry without rebuilding: `node dist/index.js` (pass your own args) |

Worker threads default to **CPU logical core count**. Set `GIANT_THREADS` before running to cap or raise parallelism (e.g. `1` for single-threaded).

---

## Command-line options

```
node dist/index.js [options]

  -f, --file <path>   JSON with { "cipher": "<base64>" } (default: project-root `cipherbase.json`, resolved from `dist/index.js`)
  --dump-all          Legacy: all scored candidates (no auto brute loop)
  --min-score <n>     With --dump-all: minimum heuristic score
  -n, --limit <n>     With --dump-all: max rows
  --jsonl             With --dump-all: one JSON object per line
  -h, --help          Show help
```

---

## Environment variables

Run `npm run help` for the canonical list embedded in the CLI. Summary:

### Brute phases (auto solve)

| Variable | Meaning |
|----------|---------|
| `GIANT_MAX_MS` | Wall time for **XOR + Vigenère/Beaufort brute only** (ms). Default `600000` (10 min). `0` = unlimited. |
| `GIANT_BRUTE_XOR_LEN` | Max repeating XOR key length over `[a-zA-Z0-9]`. Default `4`. Warns if `>3`. |
| `GIANT_BRUTE_VIG_LEN` | Max Vigenère + Beaufort key length on the **Base64 string**. Default `3`. Warns if `>3`. |
| `GIANT_PROGRESS_EVERY` | Log XOR brute progress every N tries (`0` = off). Default `250000`. |
| `GIANT_THREADS` | Worker threads for large ranges (default: CPU count; `1` = single-threaded). |
| `GIANT_EXTRA_KEYS` | Comma/semicolon-separated extra keys for heuristics (XOR, Vigenère, layered RC4, etc.). |

### Display (terminal UI)

| Variable | Meaning |
|----------|---------|
| `GIANT_UI_WIDTH` | Box width in columns (about **60–320**; default **160**). |
| `GIANT_HEX_DUMP_BYTES` | Bytes in the annotated hex panel (default **8192**; `0` or very large caps at ~1 MiB in code). |
| `GIANT_CANDIDATE_TEXT_MAX` | Optional cap on plaintext characters shown in winner/near-miss cards (omit for no cap). |

### Extended probes (heuristic pool)

| Variable | Meaning |
|----------|---------|
| `GIANT_EXTENDED_PROBES` | `0` = skip classical + block-cipher + cumulative-XOR **bundle** (and related paths). Default on. |
| `GIANT_CLASSICAL_PROBES` | `0` = skip classical letter ciphers (A26/A52 family). |
| `GIANT_BLOCK_CIPHER_PROBES` | `0` = skip OpenSSL block decrypt attempts. |
| `GIANT_EXTENDED_KEYWORDS` | Max size of merged keyword list (code default **120**; npm `solve` scripts often raise this). |
| `GIANT_CLASSICAL_KEYS` | Max keywords for classical ciphers only. |
| `GIANT_BLOCK_CIPHER_KEYS` | Max passphrases for block ciphers. |
| `GIANT_BLOCK_CIPHER_MAX` | Max successful block decrypts **per direction** (direct + reversed ciphertext). |

### COD-era classical (extended probes)

| Variable | Meaning |
|----------|---------|
| `GIANT_COD_CLASSICAL_PROBES` | `0` = skip Affine, Playfair, Bifid, columnar, keyed Caesar, ZNS Vigenère block. Default on. |
| `GIANT_COD_CLASSICAL_KEYS` | Max keywords for those methods (default **60**). |
| `GIANT_COD_AFFINE` | `0` = skip full Affine (a,b) sweep over A26. |
| `GIANT_COD_KEYED_CAESAR_MAX_SHIFT` | Max shift **1…N** for keyed Caesar (default **25**). |

### Layered transforms

| Variable | Meaning |
|----------|---------|
| `GIANT_NESTED_B64` | Max nested Base64 unwrap depth (code default **8**; npm presets often **12**). |
| `GIANT_LAYER_MAX_BUFS` | Cap on distinct buffers in the layered pass (code default **140**; presets may raise). |
| `GIANT_LAYER_XORREP` / `GIANT_LAYER_RC4` | Stretched key counts for layer XOR / RC4. |
| `GIANT_LAYER_XOR256` | Set `0` to skip 256 single-byte XOR on layer buffers. |
| `GIANT_LAYER_XOR256_MAXBUFS` | How many layer buffers get the full single-byte XOR sweep. |

### Logging

| Variable | Meaning |
|----------|---------|
| `GIANT_WORD_LOG` | Path for dictionary word-hit log (default `./giant-word-hits.log`). |

---

## What a typical run prints

1. **Cryptanalysis running** — Keyspace estimates, thread count, time budget; note about the **live brute** panel (TTY only).
2. **Live brute panel** (TTY) — During XOR/Vigenère brute: progress bar, keys tried/left, budget countdown, ETA.
3. **Hero + input** — File path, Base64 length.
4. **Cipher suite catalog** — Boxed summary of transport, XOR/stream, classical, COD-era, block, scoring (from `COD_CIPHER_SUITE_SECTIONS`).
5. **Outer Base64** — Decoded payload fingerprint (entropy, hex preview, file signatures, nested-format hints).
6. **Hex pattern scan** — Annotated hex, byte stats, single-byte XOR printable hints, structural notes.
7. **Cipher intelligence** — Consolidated signals from payload + candidate pool.
8. **Analytics dashboard** — Candidate pool stats, brute counts, transform mix.
9. **Execution pipeline** — Phases completed (heuristics, xor-brute, vig-brute, …).
10. **Dictionary token scan** — English tokens length ≥3.
11. **Word log path** — `giant-word-hits.log` (session sections plus appended payload / intelligence text).
12. **Best candidate / readability** — Solution or near-miss with strict-readability metrics.

Non-TTY (e.g. piped output): the live panel is skipped; sparse progress lines may still appear when `GIANT_PROGRESS_EVERY` allows.

---

## Project layout

```
GiantCipher/
├── package.json              # scripts, engines, dependencies
├── tsconfig.json             # TypeScript → dist/
├── cipherbase.json           # default input (you edit `cipher`)
├── giant-word-hits.log       # generated per run (see .gitignore)
├── README.md
├── tutorial.txt              # step-by-step companion to this file
├── src/
│   ├── index.ts               # CLI entry: argv parsing, --help, full session (auto-solve vs --dump-all)
│   ├── solver.ts              # load JSON, heuristic candidate generation, scoring entry
│   ├── autoSolve.ts           # orchestrates heuristics then brute XOR/Vigenère, readability gate
│   ├── bruteforce.ts          # parallel workers, key ranges, timeouts
│   ├── workers/
│   │   ├── xorRangeWorker.ts
│   │   └── vigRangeWorker.ts
│   ├── extendedProbes.ts      # classical, block, COD classical, cumulative-XOR bundle
│   ├── classicalCiphers.ts
│   ├── codClassicalCiphers.ts
│   ├── codCipherSuite.ts      # human-readable method catalog for the CLI boxes
│   ├── blockCipherProbes.ts
│   ├── layerSearch.ts         # nested B64, zlib, XOR, RC4, layer caps (GIANT_LAYER_*)
│   ├── layerTransforms.ts
│   ├── consoleUi.ts           # boxed UI: stats, phases, payload, hex, word hits
│   ├── solveProgress.ts       # banners, live brute TTY UI, interrupt progress
│   ├── cipherIntelligence.ts
│   ├── payloadAnalysis.ts
│   ├── hexPatterns.ts
│   ├── wordScan.ts            # dictionary scan + session log writer
│   ├── englishReadability.ts
│   ├── scoring.ts
│   ├── stats.ts
│   ├── transforms.ts
│   ├── keyspace.ts
│   ├── bruteState.ts
│   └── uiWidth.ts
└── dist/                      # compiled JS + .d.ts (gitignored — run `npm run build`)
```

The executable entry after build is **`dist/index.js`** (`package.json` `"main"`).

---

## Tips

- Start with `npm run solve:quick` to verify wiring; scale up with `solve`, `solve:full`, or long timed scripts when you need maximum breadth.
- **Payload / hex / intelligence** panels depend on the **decoded bytes** of `cipher` — they only change when the ciphertext changes.
- **Brute wall time** applies to the **XOR + Vigenère/Beaufort** phases after heuristics; extended probes run during earlier candidate generation (bounded by code and env).
- Use `GIANT_EXTRA_KEYS` for map-specific or community passphrase guesses without editing source.
- Disable COD or classical probes with the `GIANT_COD_*` / `GIANT_CLASSICAL_PROBES` flags when profiling speed.

---

## License

Add a `LICENSE` file in your repository if you publish this project; this README does not impose one by default.
