/**
 * Classical ciphers documented across Treyarch Zombies / COD cipher hunts
 * (Base64/hex/Vigenère/XOR are elsewhere). Affine, Playfair, Bifid, columnar
 * transposition, keyed Caesar, and custom-alphabet Vigenère appear on maps such as
 * Classified, Der Eisendrache, Zetsubou No Shima, etc.
 */
const A26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/** Modular inverse of a mod 26; null if none (a must be coprime to 26). */
export function modInv26(a) {
    for (let x = 1; x < 26; x++) {
        if ((a * x) % 26 === 1)
            return x;
    }
    return null;
}
/** Valid multipliers a mod 26 (coprime to 26). */
export const AFFINE_A_VALUES = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
/** Affine decrypt: P = a⁻¹(C − b) mod 26 on A–Z; other chars unchanged. */
export function affineDecryptA26(ciphertext, a, b) {
    const inv = modInv26(((a % 26) + 26) % 26);
    if (inv === null)
        return ciphertext;
    const bb = ((b % 26) + 26) % 26;
    let out = "";
    for (const ch of ciphertext) {
        const u = ch.toUpperCase();
        const code = u.charCodeAt(0);
        if (code < 65 || code > 90) {
            out += ch;
            continue;
        }
        const C = code - 65;
        const P = (inv * (C - bb + 26)) % 26;
        const L = A26[P];
        out += ch === ch.toUpperCase() ? L : L.toLowerCase();
    }
    return out;
}
/** Build 25-letter keyed alphabet (I/J merged) for Polybius / Playfair. */
function keyedAlphabetNoJ(keyPhrase) {
    const k = keyPhrase.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
    const seen = new Set();
    let s = "";
    for (const ch of k + A26.replace("J", "")) {
        if (ch === "J")
            continue;
        if (!seen.has(ch)) {
            seen.add(ch);
            s += ch;
        }
    }
    return s.slice(0, 25);
}
/** Full 26-letter keyed alphabet (keyword first, then unused A–Z). */
function keyedAlphabet26(keyPhrase) {
    const k = keyPhrase.toUpperCase().replace(/[^A-Z]/g, "");
    const seen = new Set();
    let s = "";
    for (const ch of k + A26) {
        if (!seen.has(ch)) {
            seen.add(ch);
            s += ch;
        }
    }
    return s.slice(0, 26);
}
const polybiusSquareCache = new Map();
function buildPolybiusSquare(keyword) {
    const cached = polybiusSquareCache.get(keyword);
    if (cached)
        return cached;
    const alpha = keyedAlphabetNoJ(keyword);
    const grid = [];
    for (let r = 0; r < 5; r++) {
        grid.push(alpha.slice(r * 5, r * 5 + 5).split(""));
    }
    const pos = new Map();
    for (let r = 0; r < 5; r++) {
        for (let c = 0; c < 5; c++) {
            pos.set(grid[r][c], [r, c]);
        }
    }
    const result = { grid, pos };
    polybiusSquareCache.set(keyword, result);
    return result;
}
/** Playfair decrypt (5×5, I/J merged). Ciphertext digraphs; ignores non-letters. */
export function playfairDecrypt(ciphertext, keyword) {
    const { grid, pos } = buildPolybiusSquare(keyword);
    const raw = ciphertext.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
    if (raw.length < 2)
        return ciphertext;
    let out = "";
    for (let i = 0; i + 1 < raw.length; i += 2) {
        const a = raw[i];
        const b = raw[i + 1];
        const p1 = pos.get(a);
        const p2 = pos.get(b);
        if (!p1 || !p2)
            continue;
        const [r1, c1] = p1;
        const [r2, c2] = p2;
        if (r1 === r2) {
            out += grid[r1][(c1 + 4) % 5] + grid[r2][(c2 + 4) % 5];
        }
        else if (c1 === c2) {
            out += grid[(r1 + 4) % 5][c1] + grid[(r2 + 4) % 5][c2];
        }
        else {
            out += grid[r1][c2] + grid[r2][c1];
        }
    }
    return out;
}
/**
 * Bifid decrypt (full-period): each ciphertext letter is a Polybius cell; the 2n coordinates
 * split into plaintext row coords (first n) and column coords (last n).
 */
export function bifidDecrypt(ciphertext, keyword) {
    const { grid, pos } = buildPolybiusSquare(keyword);
    const letters = ciphertext.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
    const n = letters.length;
    if (n < 2)
        return ciphertext;
    const flat = [];
    for (const ch of letters) {
        const p = pos.get(ch);
        if (!p)
            return ciphertext;
        flat.push(p[0], p[1]);
    }
    if (flat.length !== 2 * n)
        return ciphertext;
    const rowPlain = flat.slice(0, n);
    const colPlain = flat.slice(n);
    let out = "";
    for (let i = 0; i < n; i++) {
        out += grid[rowPlain[i]][colPlain[i]];
    }
    return out;
}
/** Columnar transposition decrypt (keyword sorts column read order). */
export function columnarTranspositionDecrypt(ciphertext, keyword) {
    const k = keyword.toUpperCase().replace(/[^A-Z]/g, "");
    if (k.length < 2)
        return ciphertext;
    const clean = ciphertext.toUpperCase().replace(/[^A-Z]/g, "");
    if (clean.length < k.length)
        return ciphertext;
    const cols = k.length;
    const rows = Math.ceil(clean.length / cols);
    const total = rows * cols;
    const padded = clean.padEnd(total, "X");
    const order = [...k.split("").map((c, i) => ({ c, i }))].sort((a, b) => a.c === b.c ? a.i - b.i : a.c.localeCompare(b.c));
    const colOrder = order.map((x) => x.i);
    const grid = Array.from({ length: rows }, () => new Array(cols).fill(""));
    let idx = 0;
    for (const ci of colOrder) {
        for (let r = 0; r < rows; r++) {
            grid[r][ci] = padded[idx++];
        }
    }
    let out = "";
    for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
            out += grid[r][c];
        }
    }
    return out.slice(0, clean.length);
}
/** Keyed substitution alphabet from phrase, then Caesar shift on that alphabet. */
export function keyedCaesarDecrypt(ciphertext, keyPhrase, shift) {
    const keyed = keyedAlphabet26(keyPhrase);
    if (keyed.length < 26)
        return ciphertext;
    const s = ((shift % 26) + 26) % 26;
    const invMap = new Map();
    for (let i = 0; i < keyed.length; i++) {
        invMap.set(keyed[i], i);
    }
    let out = "";
    for (const ch of ciphertext) {
        const u = ch.toUpperCase();
        if (u < "A" || u > "Z") {
            out += ch;
            continue;
        }
        const letter = u === "J" ? "I" : u;
        const idx = invMap.get(letter);
        if (idx === undefined) {
            out += ch;
            continue;
        }
        const p = (idx - s + 26) % 26;
        const L = keyed[p];
        out += ch === ch.toUpperCase() ? L : L.toLowerCase();
    }
    return out;
}
/** Vigenère where indices use a custom A–Z permutation (26 distinct letters). */
export function vigenereDecryptCustomAlphabet(ciphertext, key, alphabet) {
    const alpha = alphabet.toUpperCase().replace(/[^A-Z]/g, "");
    if (new Set(alpha).size !== 26)
        return ciphertext;
    const idxOf = new Map();
    for (let i = 0; i < 26; i++) {
        idxOf.set(alpha[i], i);
    }
    const k = key.toUpperCase().replace(/[^A-Z]/g, "");
    if (!k.length)
        return ciphertext;
    let ki = 0;
    let out = "";
    for (const ch of ciphertext) {
        const u = ch.toUpperCase();
        if (u < "A" || u > "Z") {
            out += ch;
            continue;
        }
        const ci = idxOf.get(u);
        if (ci === undefined) {
            out += ch;
            continue;
        }
        const kv = idxOf.get(k[ki % k.length]);
        if (kv === undefined) {
            ki++;
            out += ch;
            continue;
        }
        const pi = (ci - kv + 26) % 26;
        const L = alpha[pi];
        out += ch === ch.toUpperCase() ? L : L.toLowerCase();
        ki++;
    }
    return out;
}
/** Zetsubou No Shima cipher #11 — custom alphabet + keyword shinonuma (community solve). */
export const COD_CUSTOM_ALPHABET_ZNS = "AMUNOIHSZYXWVTRQPLKJGFEDCB";
