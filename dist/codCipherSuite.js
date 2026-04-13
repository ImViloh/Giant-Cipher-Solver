/**
 * Human-readable catalog of cipher methods this tool exercises (COD Zombies–aligned
 * plus standard cryptanalysis). Displayed in the boxed CLI UI.
 */
export const COD_CIPHER_SUITE_SECTIONS = [
    {
        title: "Transport & nested armoring",
        lines: [
            "Outer Base64 → raw bytes; Base64 alphabet rotation (64 shifts)",
            "Vigenère + Beaufort on Base64 ciphertext (keyword list)",
            "Atbash on Base64 alphabet; reverse Base64 string / decoded bytes",
            "Nested Base64 / hex ASCII / zlib–gzip / Base32 / Base58-shaped detection (payload scan)",
        ],
    },
    {
        title: "XOR & stream-style",
        lines: [
            "Single-byte XOR on decoded bytes (0x00–0xff)",
            "Repeating XOR with lore + keyword-derived keys ([a-zA-Z0-9] brute on bytes)",
            "Cumulative XOR unroll (byte[i] ⊕ byte[i−1] inverse)",
            "RC4 with expanded passphrase list (layer search)",
        ],
    },
    {
        title: "Classical (A–Z / A–z text on decoded buffer)",
        lines: [
            "Vigenère + Beaufort A26 and A52 (extended keywords)",
            "Caesar shifts (common values); ROT13; Atbash A26",
            "Rail fence transposition (rails 2–15 on compacted letters)",
        ],
    },
    {
        title: "COD-era classical (extended probes — wiki / community solves)",
        lines: [
            "Affine A26 — all valid (a,b) pairs (cod-affine-a26)",
            "Playfair 5×5 (I/J merged) — cod-playfair",
            "Bifid — cod-bifid",
            "Columnar transposition — cod-columnar",
            "Keyed Caesar on keyword-built alphabet + shift 1…25 — cod-keyed-caesar",
            "Custom-alphabet Vigenère (ZNS alphabet + keyword) — cod-vigenere-custom-zns",
        ],
    },
    {
        title: "Block & binary",
        lines: [
            "OpenSSL EVP-style tries: AES / 3DES / RC2 / Blowfish with passphrase list (normal + reversed input)",
            "Single-byte XOR on outer Base64 ASCII string (edge cases)",
        ],
    },
    {
        title: "Heuristic scoring & analysis",
        lines: [
            "English χ², letter ratio, bigrams, quadgrams; strict readability gate",
            "Payload fingerprint (entropy, magic bytes); hex pattern scan; cipher-intelligence panel",
        ],
    },
    {
        title: "COD puzzles not covered here (manual / visual tools)",
        lines: [
            "Flag semaphore, inverse graphing calculator plots, homophonic pads, Purple machine, Übchi, predictive-text ciphers",
            "These need images, auxiliary sheets, or external solvers — decode the string first, then use community tools",
        ],
    },
];
