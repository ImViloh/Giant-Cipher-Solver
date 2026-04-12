import { createHash } from "node:crypto";
import { bufferToLatin1, bufferToPrintableUtf8, scoreEnglish, } from "./scoring.js";
import { allStretchXorKeys, blundellCipherKeywords, builtinXorKeys, } from "./transforms.js";
import { atbashLettersA26, beaufortDecryptA26, beaufortDecryptA52, caesarDecryptA26, railFenceDecode, rot13A26, vigenereDecryptA26, vigenereDecryptA52, } from "./classicalCiphers.js";
import { probeBlockCiphers, probeBlockCiphersReversedInput, } from "./blockCipherProbes.js";
import { decodeCumulativeXor } from "./layerTransforms.js";
function extraKeysFromEnv() {
    const e = process.env.GIANT_EXTRA_KEYS;
    if (!e)
        return [];
    return e.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
}
function derivedMd5KeyStrings() {
    const seeds = ["ZOMBIES", "TheGiant", "Revelations", "Primis", "Group935"];
    return seeds.map((s) => createHash("md5").update(s, "utf8").digest("hex"));
}
/** Keywords for classical ciphers + block-cipher passphrases (Blundell / Treyarch / community). */
function expandedKeywordList() {
    const seen = new Set();
    const out = [];
    for (const k of [
        ...blundellCipherKeywords(),
        ...builtinXorKeys(),
        ...allStretchXorKeys(),
        ...derivedMd5KeyStrings(),
        ...extraKeysFromEnv(),
    ]) {
        if (!k || seen.has(k))
            continue;
        seen.add(k);
        out.push(k);
    }
    const max = Math.max(40, Math.min(200, Number.parseInt(process.env.GIANT_EXTENDED_KEYWORDS ?? "120", 10) || 120));
    return out.slice(0, max);
}
function pushStringCandidates(out, method, detail, text) {
    const meta = scoreEnglish(text);
    out.push({ method, detail, text, score: meta.score, meta });
}
function pushBufferCandidates(out, method, detail, buf) {
    const u8 = bufferToPrintableUtf8(buf);
    if (u8 !== null) {
        const meta = scoreEnglish(u8);
        out.push({
            method,
            detail: `${detail} (utf8)`,
            text: u8,
            score: meta.score,
            meta,
        });
    }
    const lat = bufferToLatin1(buf);
    const meta2 = scoreEnglish(lat);
    out.push({
        method,
        detail: `${detail} (latin1)`,
        text: lat,
        score: meta2.score,
        meta: meta2,
    });
}
/**
 * Classical letter ciphers, OpenSSL block tries (AES / 3DES / RC2* / BF*), and reversed-input variants.
 * Disable entirely with `GIANT_EXTENDED_PROBES=0`.
 */
export function collectExtendedProbeCandidates(decoded) {
    if ((process.env.GIANT_EXTENDED_PROBES ?? "1") === "0")
        return [];
    const out = [];
    pushBufferCandidates(out, "transform-cumulative-xor-unroll", "c[i] ⊕ c[i−1] inverse", decodeCumulativeXor(decoded));
    const keys = expandedKeywordList();
    const classicalKeys = keys.slice(0, Math.min(keys.length, Number.parseInt(process.env.GIANT_CLASSICAL_KEYS ?? "80", 10) || 80));
    const latin = bufferToLatin1(decoded);
    if ((process.env.GIANT_CLASSICAL_PROBES ?? "1") !== "0") {
        for (const k of classicalKeys) {
            pushStringCandidates(out, "classical-beaufort-a26", `key="${k}"`, beaufortDecryptA26(latin, k));
            pushStringCandidates(out, "classical-vigenere-a26", `key="${k}"`, vigenereDecryptA26(latin, k));
            pushStringCandidates(out, "classical-beaufort-a52", `key="${k}"`, beaufortDecryptA52(latin, k));
            pushStringCandidates(out, "classical-vigenere-a52", `key="${k}"`, vigenereDecryptA52(latin, k));
        }
        pushStringCandidates(out, "classical-atbash-a26", "", atbashLettersA26(latin));
        pushStringCandidates(out, "classical-rot13", "", rot13A26(latin));
        for (const s of [1, 3, 5, 7, 11, 13, 17, 19, 23]) {
            pushStringCandidates(out, "classical-caesar", `shift=${s}`, caesarDecryptA26(latin, s));
        }
        const compact = latin.replace(/\s/g, "");
        if (compact.length >= 8) {
            const maxRails = Math.min(12, Math.max(2, Math.floor(compact.length / 4)));
            for (let rails = 2; rails <= maxRails; rails++) {
                pushStringCandidates(out, "classical-rail-fence", `rails=${rails}`, railFenceDecode(compact, rails));
            }
        }
    }
    if ((process.env.GIANT_BLOCK_CIPHER_PROBES ?? "1") !== "0") {
        const blockPw = keys.slice(0, Math.min(keys.length, Number.parseInt(process.env.GIANT_BLOCK_CIPHER_KEYS ?? "48", 10) || 48));
        const mh = Math.min(120, Math.max(1, Number.parseInt(process.env.GIANT_BLOCK_CIPHER_MAX ?? "80", 10) || 80));
        for (const hit of [
            ...probeBlockCiphers(decoded, blockPw, mh),
            ...probeBlockCiphersReversedInput(decoded, blockPw, mh),
        ]) {
            pushBufferCandidates(out, `block-${hit.algorithm}`, `${hit.password} | ${hit.derivation}`, hit.plain);
        }
    }
    return out;
}
