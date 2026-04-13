import { createHash } from "node:crypto";
import {
  bufferToLatin1,
  bufferToPrintableUtf8,
  scoreEnglish,
} from "./scoring.js";
import type { Candidate } from "./solver.js";
import {
  allStretchXorKeys,
  blundellCipherKeywords,
  builtinXorKeys,
} from "./transforms.js";
import {
  AFFINE_A_VALUES,
  bifidDecrypt,
  COD_CUSTOM_ALPHABET_ZNS,
  columnarTranspositionDecrypt,
  affineDecryptA26,
  keyedCaesarDecrypt,
  playfairDecrypt,
  vigenereDecryptCustomAlphabet,
} from "./codClassicalCiphers.js";
import {
  atbashLettersA26,
  beaufortDecryptA26,
  beaufortDecryptA52,
  caesarDecryptA26,
  railFenceDecode,
  rot13A26,
  vigenereDecryptA26,
  vigenereDecryptA52,
} from "./classicalCiphers.js";
import {
  probeBlockCiphers,
  probeBlockCiphersReversedInput,
} from "./blockCipherProbes.js";
import { decodeCumulativeXor } from "./layerTransforms.js";

function extraKeysFromEnv(): string[] {
  const e = process.env.GIANT_EXTRA_KEYS;
  if (!e) return [];
  return e.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
}

function derivedMd5KeyStrings(): string[] {
  const seeds = ["ZOMBIES", "TheGiant", "Revelations", "Primis", "Group935"];
  return seeds.map((s) => createHash("md5").update(s, "utf8").digest("hex"));
}

/** Keywords for classical ciphers + block-cipher passphrases (Blundell / Treyarch / community). */
function expandedKeywordList(): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const k of [
    ...blundellCipherKeywords(),
    ...builtinXorKeys(),
    ...allStretchXorKeys(),
    ...derivedMd5KeyStrings(),
    ...extraKeysFromEnv(),
  ]) {
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  const max = Math.max(
    40,
    Math.min(
      200,
      Number.parseInt(process.env.GIANT_EXTENDED_KEYWORDS ?? "120", 10) || 120,
    ),
  );
  return out.slice(0, max);
}

function pushStringCandidates(
  out: Candidate[],
  method: string,
  detail: string,
  text: string,
): void {
  const meta = scoreEnglish(text);
  out.push({ method, detail, text, score: meta.score, meta });
}

function pushBufferCandidates(
  out: Candidate[],
  method: string,
  detail: string,
  buf: Buffer,
): void {
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
export function collectExtendedProbeCandidates(decoded: Buffer): Candidate[] {
  if ((process.env.GIANT_EXTENDED_PROBES ?? "1") === "0") return [];

  const out: Candidate[] = [];

  pushBufferCandidates(
    out,
    "transform-cumulative-xor-unroll",
    "c[i] ⊕ c[i−1] inverse",
    decodeCumulativeXor(decoded),
  );
  const keys = expandedKeywordList();
  const classicalKeys = keys.slice(
    0,
    Math.min(
      keys.length,
      Number.parseInt(process.env.GIANT_CLASSICAL_KEYS ?? "80", 10) || 80,
    ),
  );
  const latin = bufferToLatin1(decoded);

  if ((process.env.GIANT_CLASSICAL_PROBES ?? "1") !== "0") {
    for (const k of classicalKeys) {
      pushStringCandidates(
        out,
        "classical-beaufort-a26",
        `key="${k}"`,
        beaufortDecryptA26(latin, k),
      );
      pushStringCandidates(
        out,
        "classical-vigenere-a26",
        `key="${k}"`,
        vigenereDecryptA26(latin, k),
      );
      pushStringCandidates(
        out,
        "classical-beaufort-a52",
        `key="${k}"`,
        beaufortDecryptA52(latin, k),
      );
      pushStringCandidates(
        out,
        "classical-vigenere-a52",
        `key="${k}"`,
        vigenereDecryptA52(latin, k),
      );
    }

    pushStringCandidates(out, "classical-atbash-a26", "", atbashLettersA26(latin));
    pushStringCandidates(out, "classical-rot13", "", rot13A26(latin));

    for (const s of [1, 3, 5, 7, 11, 13, 17, 19, 23]) {
      pushStringCandidates(
        out,
        "classical-caesar",
        `shift=${s}`,
        caesarDecryptA26(latin, s),
      );
    }

    const compact = latin.replace(/\s/g, "");
    if (compact.length >= 8) {
      const maxRails = Math.min(
        15,
        Math.max(2, Math.floor(compact.length / 4)),
      );
      for (let rails = 2; rails <= maxRails; rails++) {
        pushStringCandidates(
          out,
          "classical-rail-fence",
          `rails=${rails}`,
          railFenceDecode(compact, rails),
        );
      }
    }

    if ((process.env.GIANT_COD_CLASSICAL_PROBES ?? "1") !== "0") {
      const codKeyCap = Math.min(
        classicalKeys.length,
        Math.max(
          8,
          Number.parseInt(process.env.GIANT_COD_CLASSICAL_KEYS ?? "60", 10) || 60,
        ),
      );
      const codKeys = classicalKeys.slice(0, codKeyCap);
      const codKeyedCaesarMaxShift = Math.min(
        25,
        Math.max(
          1,
          Number.parseInt(
            process.env.GIANT_COD_KEYED_CAESAR_MAX_SHIFT ?? "25",
            10,
          ) || 25,
        ),
      );

      if ((process.env.GIANT_COD_AFFINE ?? "1") !== "0") {
        for (const a of AFFINE_A_VALUES) {
          for (let b = 0; b < 26; b++) {
            pushStringCandidates(
              out,
              "cod-affine-a26",
              `a=${a} b=${b}`,
              affineDecryptA26(latin, a, b),
            );
          }
        }
      }

      for (const k of codKeys) {
        pushStringCandidates(
          out,
          "cod-playfair",
          `key="${k}"`,
          playfairDecrypt(latin, k),
        );
        pushStringCandidates(
          out,
          "cod-bifid",
          `key="${k}"`,
          bifidDecrypt(latin, k),
        );
        pushStringCandidates(
          out,
          "cod-columnar",
          `key="${k}"`,
          columnarTranspositionDecrypt(latin, k),
        );
        for (let s = 1; s <= codKeyedCaesarMaxShift; s++) {
          pushStringCandidates(
            out,
            "cod-keyed-caesar",
            `key="${k}" shift=${s}`,
            keyedCaesarDecrypt(latin, k, s),
          );
        }
        pushStringCandidates(
          out,
          "cod-vigenere-custom-zns",
          `alphabet=ZNS key="${k}"`,
          vigenereDecryptCustomAlphabet(latin, k, COD_CUSTOM_ALPHABET_ZNS),
        );
      }
    }
  }

  if ((process.env.GIANT_BLOCK_CIPHER_PROBES ?? "1") !== "0") {
    const blockPw = keys.slice(
      0,
      Math.min(
        keys.length,
        Number.parseInt(process.env.GIANT_BLOCK_CIPHER_KEYS ?? "48", 10) || 48,
      ),
    );
    const mh = Math.min(
      120,
      Math.max(
        1,
        Number.parseInt(process.env.GIANT_BLOCK_CIPHER_MAX ?? "80", 10) || 80,
      ),
    );
    for (const hit of [
      ...probeBlockCiphers(decoded, blockPw, mh),
      ...probeBlockCiphersReversedInput(decoded, blockPw, mh),
    ]) {
      pushBufferCandidates(
        out,
        `block-${hit.algorithm}`,
        `${hit.password} | ${hit.derivation}`,
        hit.plain,
      );
    }
  }

  return out;
}
