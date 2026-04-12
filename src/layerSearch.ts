import {
  bufferToLatin1,
  bufferToPrintableUtf8,
  scoreEnglish,
} from "./scoring.js";
import type { Candidate } from "./solver.js";
import { allStretchXorKeys, xorBuffer, xorSingleByte } from "./transforms.js";
import {
  bufHashShort,
  collectNestedBase64,
  looksLikeBase64Text,
  rc4Transform,
  swapNibbles,
  tryHexAsciiDecode,
  tryZlibVariants,
  looksLikeHexAscii,
} from "./layerTransforms.js";

function extraKeysFromEnv(): string[] {
  const e = process.env.GIANT_EXTRA_KEYS;
  if (!e) return [];
  return e.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
}

function pushCand(
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

function keyMaterial(k: string): Buffer {
  if (/^[0-9a-fA-F]+$/.test(k) && k.length >= 8 && k.length % 2 === 0) {
    try {
      const b = Buffer.from(k, "hex");
      if (b.length > 0) return b;
    } catch {
      /* utf8 */
    }
  }
  return Buffer.from(k, "utf8");
}

/**
 * Second-stage transforms on the Base64-decoded payload: nested Base64, zlib,
 * hex, nibble swap, then XOR / RC4 with an expanded key list.
 * Bounded by env (see GIANT_LAYER_*).
 */
export function collectLayeredCandidates(decoded: Buffer): Candidate[] {
  const out: Candidate[] = [];

  const nestDepth = Math.min(
    12,
    Math.max(1, Number.parseInt(process.env.GIANT_NESTED_B64 ?? "8", 10) || 8),
  );
  const maxBufs = Math.min(
    400,
    Math.max(8, Number.parseInt(process.env.GIANT_LAYER_MAX_BUFS ?? "140", 10) || 140),
  );
  const maxXorRep = Math.min(
    220,
    Math.max(24, Number.parseInt(process.env.GIANT_LAYER_XORREP ?? "140", 10) || 140),
  );
  const maxRc4 = Math.min(
    220,
    Math.max(24, Number.parseInt(process.env.GIANT_LAYER_RC4 ?? "140", 10) || 140),
  );
  const doXor256 = (process.env.GIANT_LAYER_XOR256 ?? "1") !== "0";
  const xor256MaxBufs = Math.min(
    maxBufs,
    Math.max(
      0,
      Number.parseInt(process.env.GIANT_LAYER_XOR256_MAXBUFS ?? "56", 10) || 56,
    ),
  );

  const stretch = [...allStretchXorKeys(), ...extraKeysFromEnv()];
  const xorRepKeys = stretch.slice(0, maxXorRep);
  const rc4Keys = stretch.slice(0, maxRc4);

  const seen = new Set<string>();
  const layers: { buf: Buffer; path: string }[] = [];

  function addBuf(buf: Buffer, path: string): void {
    const h = bufHashShort(buf);
    if (seen.has(h)) return;
    if (layers.length >= maxBufs) return;
    seen.add(h);
    layers.push({ buf, path });
  }

  const nested = collectNestedBase64(decoded, nestDepth);
  for (const lb of nested) addBuf(lb.buf, lb.path);

  for (const lb of nested) {
    if (looksLikeHexAscii(lb.buf)) {
      const hx = tryHexAsciiDecode(lb.buf);
      if (hx && hx.length > 0) addBuf(hx, `${lb.path}->hex`);
    }
    const z = tryZlibVariants(lb.buf);
    if (z && z.length > 0) addBuf(z, `${lb.path}->zlib`);
    addBuf(swapNibbles(lb.buf), `${lb.path}->nibble-swap`);
  }

  const snapshot = [...layers];
  for (const lb of snapshot) {
    if (!looksLikeBase64Text(lb.buf)) continue;
    const inner = collectNestedBase64(lb.buf, Math.min(6, nestDepth));
    for (let j = 1; j < inner.length; j++) {
      const x = inner[j]!;
      addBuf(x.buf, `${lb.path}|${x.path}`);
    }
  }

  for (let li = 0; li < layers.length; li++) {
    const { buf, path } = layers[li]!;
    pushCand(out, "layer-raw", path, buf);

    if (doXor256 && li < xor256MaxBufs) {
      for (let b = 0; b < 256; b++) {
        pushCand(
          out,
          "layer-xor1",
          `${path} key=0x${b.toString(16).padStart(2, "0")}`,
          xorSingleByte(buf, b),
        );
      }
    }

    for (const k of xorRepKeys) {
      pushCand(out, "layer-xor-rep", `${path} key="${k}"`, xorBuffer(buf, k));
    }

    for (const k of rc4Keys) {
      pushCand(
        out,
        "layer-rc4",
        `${path} rc4 key="${k}"`,
        rc4Transform(buf, keyMaterial(k)),
      );
    }
  }

  return out;
}
