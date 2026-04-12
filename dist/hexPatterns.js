/**
 * Heuristic hex / binary structure analysis on decoded ciphertext to surface
 * patterns that suggest next cryptanalysis steps (XOR, ECB, periodicity, etc.).
 */
/** Shown in UI / log as annotated hex (first N bytes). */
export const HEX_PATTERN_PREVIEW_BYTES = 128;
const BYTES_PER_LINE = 16;
function printableAsciiStrict(b) {
    return b >= 0x20 && b <= 0x7e;
}
function xorSingle(buf, k) {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++)
        out[i] = buf[i] ^ k;
    return out;
}
function scorePrintableRatio(buf) {
    if (buf.length === 0)
        return 0;
    let n = 0;
    for (let i = 0; i < buf.length; i++) {
        if (printableAsciiStrict(buf[i]))
            n++;
    }
    return n / buf.length;
}
/** Best single-byte XOR keys by strict printable ratio (for “try this next” hints). */
function topXorPrintableKeys(buf, topN = 4) {
    if (buf.length === 0)
        return [];
    const scored = [];
    for (let k = 0; k < 256; k++) {
        const x = xorSingle(buf, k);
        scored.push({ keyByte: k, printableRatio: scorePrintableRatio(x) });
    }
    scored.sort((a, b) => b.printableRatio - a.printableRatio);
    return scored.slice(0, topN);
}
function buildAnnotatedDump(buf, maxBytes) {
    const n = Math.min(buf.length, maxBytes);
    const lines = [];
    for (let off = 0; off < n; off += BYTES_PER_LINE) {
        const slice = buf.subarray(off, Math.min(off + BYTES_PER_LINE, n));
        const hexParts = [];
        let ascii = "";
        for (let i = 0; i < slice.length; i++) {
            const b = slice[i];
            hexParts.push(b.toString(16).padStart(2, "0"));
            ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "·";
        }
        lines.push({
            offset: off.toString(16).padStart(8, "0"),
            hex: hexParts.join(" "),
            ascii,
        });
    }
    return lines;
}
function countUnique(buf) {
    const seen = new Uint8Array(256);
    let u = 0;
    for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        if (seen[b] === 0) {
            seen[b] = 1;
            u++;
        }
    }
    return u;
}
function topByteCounts(buf, k) {
    const c = new Uint32Array(256);
    for (let i = 0; i < buf.length; i++)
        c[buf[i]]++;
    const pairs = [];
    for (let b = 0; b < 256; b++) {
        if (c[b] > 0)
            pairs.push({ b, count: c[b] });
    }
    pairs.sort((a, b) => b.count - a.count);
    const n = buf.length;
    return pairs.slice(0, k).map((p) => ({
        hex: p.b.toString(16).padStart(2, "0"),
        count: p.count,
        pct: n > 0 ? (100 * p.count) / n : 0,
    }));
}
/** Same 16-byte block at two different 16-aligned offsets → ECB-style hint. */
function findAlignedDuplicateBlocks(buf, blockSize) {
    const finds = [];
    if (buf.length < blockSize * 2)
        return finds;
    const map = new Map();
    for (let off = 0; off + blockSize <= buf.length; off += blockSize) {
        const key = buf.subarray(off, off + blockSize).toString("hex");
        const prev = map.get(key);
        if (prev !== undefined && prev !== off) {
            finds.push({
                title: `Repeated ${blockSize}-byte block`,
                detail: `Identical ${blockSize}-byte pattern at offset 0x${prev.toString(16)} and 0x${off.toString(16)}.`,
                suggest: blockSize === 16
                    ? "If ciphertext: possible ECB mode or structured padding; if plaintext: repeated delimiter/header."
                    : "May indicate block-aligned framing or weak duplication in the transform.",
            });
            if (finds.length >= 4)
                break;
        }
        else {
            map.set(key, off);
        }
    }
    return finds;
}
/** Autocorrelation-lite: high agreement with shift p suggests periodic structure. */
function detectPeriod(buf) {
    if (buf.length < 12)
        return null;
    const maxP = Math.min(64, Math.floor(buf.length / 3));
    let bestP = 0;
    let bestScore = 0;
    for (let p = 2; p <= maxP; p++) {
        let match = 0;
        const lim = buf.length - p;
        for (let i = 0; i < lim; i++) {
            if (buf[i] === buf[i + p])
                match++;
        }
        const score = lim > 0 ? match / lim : 0;
        if (score > bestScore) {
            bestScore = score;
            bestP = p;
        }
    }
    if (bestP > 0 && bestScore > 0.35) {
        return {
            title: `Byte alignment at period ${bestP}`,
            detail: `~${(bestScore * 100).toFixed(0)}% of positions match byte at index+i vs i+${bestP} (rough periodicity test).`,
            suggest: "Could be XOR with repeating key shorter than buffer, a patterned keystream, or coincidental — try Vigenère / repeating XOR in the solver.",
        };
    }
    return null;
}
function longestConstantRun(buf) {
    if (buf.length === 0)
        return null;
    let bestStart = 0;
    let bestLen = 1;
    let runStart = 0;
    for (let i = 1; i <= buf.length; i++) {
        if (i === buf.length || buf[i] !== buf[i - 1]) {
            const len = i - runStart;
            if (len > bestLen) {
                bestLen = len;
                bestStart = runStart;
            }
            runStart = i;
        }
    }
    if (bestLen >= 4) {
        const b = buf[bestStart];
        return {
            title: "Long run of identical bytes",
            detail: `${bestLen}× 0x${b.toString(16).padStart(2, "0")} starting at offset 0x${bestStart.toString(16)}.`,
            suggest: "Often null padding, delimiter runs, or low-entropy regions — compare with expected plaintext framing.",
        };
    }
    return null;
}
function dominantDelta(buf) {
    if (buf.length < 8)
        return null;
    const c = new Uint32Array(256);
    for (let i = 0; i < buf.length - 1; i++) {
        const d = (buf[i + 1] - buf[i] + 256) & 255;
        c[d]++;
    }
    let bestD = 0;
    let best = 0;
    for (let d = 0; d < 256; d++) {
        if (c[d] > best) {
            best = c[d];
            bestD = d;
        }
    }
    const ratio = best / (buf.length - 1);
    if (ratio > 0.28) {
        return {
            title: "Dominant byte-to-byte step",
            detail: `Step (b[i+1]−b[i]) mod 256 = 0x${bestD.toString(16).padStart(2, "0")} in ~${(ratio * 100).toFixed(0)}% of adjacent pairs.`,
            suggest: "May indicate a ramp, counter, or simple additive structure — try subtracting a linear trend or differencing before other transforms.",
        };
    }
    return null;
}
function constantXorNeighbour(buf) {
    if (buf.length < 6)
        return null;
    const x = buf[0] ^ buf[1];
    for (let i = 1; i < buf.length - 1; i++) {
        if ((buf[i] ^ buf[i + 1]) !== x)
            return null;
    }
    return {
        title: "Constant XOR between neighbours",
        detail: `b[i] ⊕ b[i+1] = 0x${x.toString(16).padStart(2, "0")} for all adjacent pairs.`,
        suggest: "Strongly structured (not typical i.i.d. ciphertext) — may be encoding artifact or reversible with a tiny state machine.",
    };
}
/**
 * Structural / statistical scan of raw bytes after Base64 decode.
 */
export function analyzeHexPatterns(buf) {
    if (buf.length === 0) {
        return {
            annotatedLines: [],
            finds: [],
            uniqueByteValues: 0,
            topBytes: [],
            xorHints: [],
        };
    }
    const finds = [];
    finds.push(...findAlignedDuplicateBlocks(buf, 16));
    finds.push(...findAlignedDuplicateBlocks(buf, 8));
    const period = detectPeriod(buf);
    if (period)
        finds.push(period);
    const run = longestConstantRun(buf);
    if (run)
        finds.push(run);
    const delta = dominantDelta(buf);
    if (delta)
        finds.push(delta);
    const neigh = constantXorNeighbour(buf);
    if (neigh)
        finds.push(neigh);
    const u = countUnique(buf);
    if (buf.length >= 16) {
        const flatness = u / Math.min(256, buf.length);
        if (flatness > 0.85 && buf.length >= 32) {
            finds.push({
                title: "High byte diversity",
                detail: `${u} distinct byte values in ${buf.length} bytes — distribution looks broad.`,
                suggest: "Consistent with keyed encryption or compression; structural tests above matter more than byte skew.",
            });
        }
        else if (flatness < 0.25 && buf.length >= 16) {
            finds.push({
                title: "Limited byte alphabet",
                detail: `Only ~${u} distinct byte values — distribution is concentrated.`,
                suggest: "May be simple substitution, constrained encoding, or partially structured plaintext.",
            });
        }
    }
    const xorHints = topXorPrintableKeys(buf, 4);
    const best = xorHints[0];
    if (best && best.printableRatio > 0.35) {
        finds.push({
            title: "Single-byte XOR raises printability",
            detail: `Key 0x${best.keyByte.toString(16).padStart(2, "0")} gives ~${(best.printableRatio * 100).toFixed(0)}% strict printable ASCII (letters/symbols).`,
            suggest: "Solver already tries XOR-1byte on decoded bytes — compare candidate scores if this key ranks high.",
        });
    }
    return {
        annotatedLines: buildAnnotatedDump(buf, HEX_PATTERN_PREVIEW_BYTES),
        finds,
        uniqueByteValues: u,
        topBytes: topByteCounts(buf, 5),
        xorHints,
    };
}
