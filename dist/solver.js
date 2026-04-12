import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scoreEnglish, bufferToLatin1, bufferToPrintableUtf8, } from "./scoring.js";
import { allStretchXorKeys, beaufortBase64Decrypt, reverseBuffer, atbashBase64, rotateBase64Alphabet, safeBase64Decode, vigenereBase64Decrypt, xorBuffer, xorSingleByte, } from "./transforms.js";
import { collectLayeredCandidates } from "./layerSearch.js";
const __dirname = dirname(fileURLToPath(import.meta.url));
export function loadCipherJson(path) {
    const raw = readFileSync(path, "utf8");
    const j = JSON.parse(raw);
    if (typeof j.cipher !== "string" || !j.cipher.length) {
        throw new Error("cipherbase.json must contain a non-empty string field 'cipher'");
    }
    return j;
}
function push(out, method, detail, text) {
    const meta = scoreEnglish(text);
    out.push({
        method,
        detail,
        text,
        score: meta.score,
        meta,
    });
}
function tryDecodeBuffer(out, method, detail, buf) {
    const u8 = bufferToPrintableUtf8(buf);
    if (u8 !== null)
        push(out, method, `${detail} (utf8)`, u8);
    push(out, method, `${detail} (latin1)`, bufferToLatin1(buf));
}
/** Extra keyword list for Vigenère / XOR — extend without code changes via env GIANT_EXTRA_KEYS=foo,bar */
function extraKeysFromEnv() {
    const e = process.env.GIANT_EXTRA_KEYS;
    if (!e)
        return [];
    return e.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
}
function allVigenereKeys() {
    const base = [...allStretchXorKeys(), ...extraKeysFromEnv()];
    const seen = new Set();
    const keys = [];
    for (const k of base) {
        if (!seen.has(k)) {
            seen.add(k);
            keys.push(k);
        }
    }
    return keys;
}
/**
 * Run every implemented heuristic / brute step and collect scored candidates.
 */
export function solveCipherString(cipherB64) {
    const candidates = [];
    const decoded = safeBase64Decode(cipherB64);
    if (!decoded) {
        push(candidates, "error", "base64 decode failed", cipherB64);
        return candidates;
    }
    push(candidates, "baseline", "raw base64 → utf8", cipherB64);
    tryDecodeBuffer(candidates, "baseline", "decoded binary (no transform)", decoded);
    // --- XOR on raw decoded bytes ---
    for (let b = 0; b < 256; b++) {
        const x = xorSingleByte(decoded, b);
        tryDecodeBuffer(candidates, "xor-1byte", `key=0x${b.toString(16).padStart(2, "0")}`, x);
    }
    const xorKeys = [...allStretchXorKeys(), ...extraKeysFromEnv()];
    for (const k of xorKeys) {
        const x = xorBuffer(decoded, k);
        tryDecodeBuffer(candidates, "xor-repeat", `key="${k}"`, x);
    }
    const rev = reverseBuffer(decoded);
    tryDecodeBuffer(candidates, "reverse-bytes", "reverse decoded buffer", rev);
    const atbash = atbashBase64(cipherB64);
    const atbashBuf = safeBase64Decode(atbash);
    if (atbashBuf) {
        tryDecodeBuffer(candidates, "b64-atbash", "atbash on b64 alphabet", atbashBuf);
    }
    // --- Base64 alphabet rotations (before standard decode) ---
    for (let r = 0; r < 64; r++) {
        const rotated = rotateBase64Alphabet(cipherB64, r);
        const buf = safeBase64Decode(rotated);
        if (buf) {
            tryDecodeBuffer(candidates, "b64-rotate", `shift +${r} in b64 alphabet`, buf);
        }
    }
    // --- Vigenère / Beaufort on Base64 layer, then decode ---
    for (const k of allVigenereKeys()) {
        const vig = vigenereBase64Decrypt(cipherB64, k);
        const buf = safeBase64Decode(vig);
        if (buf) {
            tryDecodeBuffer(candidates, "vigenere-b64", `key="${k}"`, buf);
        }
        const beau = beaufortBase64Decrypt(cipherB64, k);
        const buf2 = safeBase64Decode(beau);
        if (buf2) {
            tryDecodeBuffer(candidates, "beaufort-b64", `key="${k}"`, buf2);
        }
    }
    // Reversed ciphertext string (community sometimes tries)
    const revStr = cipherB64.split("").reverse().join("");
    const decRev = safeBase64Decode(revStr);
    if (decRev) {
        tryDecodeBuffer(candidates, "reverse-b64-string", "ciphertext reversed", decRev);
    }
    // XOR single byte on base64 *string* bytes then decode (unlikely but cheap)
    const b64Buf = Buffer.from(cipherB64.replace(/\s/g, ""), "ascii");
    for (const xb of [0x20, 0x0d, 0x0a, 0xff]) {
        const xored = xorSingleByte(b64Buf, xb);
        const asStr = xored.toString("ascii");
        const buf = safeBase64Decode(asStr);
        if (buf) {
            tryDecodeBuffer(candidates, "xor-b64-string", `single byte 0x${xb.toString(16)} on ascii`, buf);
        }
    }
    candidates.push(...collectLayeredCandidates(decoded));
    return candidates;
}
export function defaultCipherPath() {
    return join(__dirname, "..", "cipherbase.json");
}
export function dedupeAndSort(candidates) {
    const seen = new Set();
    const uniq = [];
    for (const c of candidates) {
        const key = `${c.method}|${c.detail}|${c.text}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        uniq.push(c);
    }
    uniq.sort((a, b) => b.score - a.score);
    return uniq;
}
