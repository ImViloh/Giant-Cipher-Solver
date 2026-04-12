import pc from "picocolors";
import { analyzeEnglishReadability, englishReadabilityRank, isFullyEnglishReadable, } from "./englishReadability.js";
import { printVigBruteProgress, printXorBruteProgress, } from "./solveProgress.js";
import { bruteXorAlphanumeric, bruteVigenereB64Alphanumeric, } from "./bruteforce.js";
import { scoreEnglish } from "./scoring.js";
import { dedupeAndSort, solveCipherString } from "./solver.js";
import { safeBase64Decode } from "./transforms.js";
import { resetBruteProgress, setBruteProgress } from "./bruteState.js";
function parseMaxMs() {
    const raw = process.env.GIANT_MAX_MS;
    if (raw === undefined || raw === "")
        return 600_000;
    const p = Number.parseInt(raw, 10);
    if (!Number.isFinite(p))
        return 600_000;
    if (p <= 0)
        return 0;
    return p;
}
function defaultOptions() {
    const xorLen = Number.parseInt(process.env.GIANT_BRUTE_XOR_LEN ?? "4", 10) || 4;
    if (xorLen > 4) {
        console.warn(pc.yellow("[giant-cipher] GIANT_BRUTE_XOR_LEN>4 searches 62^5+ keys and may run a very long time."));
    }
    const peRaw = Number.parseInt(process.env.GIANT_PROGRESS_EVERY ?? "250000", 10);
    const pe = Number.isFinite(peRaw)
        ? peRaw < 0
            ? 0
            : peRaw
        : 250_000;
    return {
        bruteMaxXorKeyLen: Math.min(6, Math.max(1, xorLen)),
        bruteMaxVigKeyLen: Math.min(3, Number.parseInt(process.env.GIANT_BRUTE_VIG_LEN ?? "3", 10) || 3),
        maxMs: parseMaxMs(),
        progressEvery: pe,
    };
}
/** Resolved options (env) for UI preview before `runAutomaticSolve`. */
export function getPublicSolveOptions() {
    return { ...defaultOptions() };
}
function candidateFromHit(method, detail, text) {
    const meta = scoreEnglish(text);
    return {
        method,
        detail,
        text,
        score: meta.score,
        meta,
    };
}
function findBestNearMiss(candidates) {
    let best;
    let bestRank = -Infinity;
    for (const c of candidates) {
        const r = englishReadabilityRank(c.text);
        if (r > bestRank) {
            bestRank = r;
            best = c;
        }
    }
    return best;
}
/** First candidate whose text passes strict English, else best near-miss. */
function scanHeuristicCandidates(cipherB64) {
    const all = dedupeAndSort(solveCipherString(cipherB64));
    for (const c of all) {
        if (isFullyEnglishReadable(c.text)) {
            return { hit: c, near: c, all };
        }
    }
    return { hit: null, near: findBestNearMiss(all), all };
}
/**
 * 1) Heuristics (known keys + rotations + single-byte XOR, …).
 * 2) Full brute: repeating XOR with keys in [a-zA-Z0-9]^1..L on decoded bytes.
 * 3) Full brute: Vigenère + Beaufort on Base64 with same alphabet, key length 1..L.
 */
export async function runAutomaticSolve(cipherB64, options = {}) {
    const o = { ...defaultOptions(), ...options };
    const phases = ["heuristics"];
    resetBruteProgress();
    setBruteProgress({ phase: "heuristics" });
    const { hit, near } = scanHeuristicCandidates(cipherB64);
    if (hit) {
        return {
            solved: true,
            solution: hit,
            readability: analyzeEnglishReadability(hit.text),
            nearMiss: hit,
            xorKeysTried: 0,
            vigKeysTried: 0,
            xorTimedOut: false,
            vigTimedOut: false,
            phases,
        };
    }
    const decoded = safeBase64Decode(cipherB64);
    if (!decoded) {
        return {
            solved: false,
            nearMiss: near,
            xorKeysTried: 0,
            vigKeysTried: 0,
            xorTimedOut: false,
            vigTimedOut: false,
            phases: [...phases, "base64-decode-failed"],
        };
    }
    phases.push(`xor-alphanum-len-1..${o.bruteMaxXorKeyLen}`);
    const xorOut = await bruteXorAlphanumeric(decoded, o.bruteMaxXorKeyLen, o.maxMs, (phase, tried, keyLen) => {
        if (o.progressEvery > 0 &&
            tried > 0 &&
            tried % o.progressEvery === 0) {
            printXorBruteProgress(phase, tried, keyLen);
        }
    });
    if (xorOut.hit) {
        const c = candidateFromHit("xor-brute-alphanum", `key="${xorOut.hit.key}"`, xorOut.hit.text);
        return {
            solved: true,
            solution: c,
            readability: analyzeEnglishReadability(xorOut.hit.text),
            nearMiss: c,
            xorKeysTried: xorOut.tried,
            vigKeysTried: 0,
            xorTimedOut: xorOut.timedOut,
            vigTimedOut: false,
            phases: [...phases, "xor-brute-hit"],
        };
    }
    phases.push(`vig-b64-alphanum-len-1..${o.bruteMaxVigKeyLen}`);
    const vigReportEvery = Math.max(5000, Math.floor(o.progressEvery / 4));
    const vigOut = await bruteVigenereB64Alphanumeric(cipherB64, o.bruteMaxVigKeyLen, o.maxMs, (phase, tried) => {
        if (o.progressEvery > 0 &&
            tried > 0 &&
            tried % vigReportEvery === 0) {
            printVigBruteProgress(phase, tried);
        }
    });
    if (vigOut.hit) {
        const c = candidateFromHit(vigOut.hit.mode, `alphanum key="${vigOut.hit.key}"`, vigOut.hit.text);
        return {
            solved: true,
            solution: c,
            readability: analyzeEnglishReadability(vigOut.hit.text),
            nearMiss: c,
            xorKeysTried: xorOut.tried,
            vigKeysTried: vigOut.tried,
            xorTimedOut: xorOut.timedOut,
            vigTimedOut: vigOut.timedOut,
            phases: [...phases, "vig-brute-hit"],
        };
    }
    const fallbackNear = near ?? findBestNearMiss(dedupeAndSort(solveCipherString(cipherB64)));
    return {
        solved: false,
        nearMiss: fallbackNear,
        xorKeysTried: xorOut.tried,
        vigKeysTried: vigOut.tried,
        xorTimedOut: xorOut.timedOut,
        vigTimedOut: vigOut.timedOut,
        phases: [...phases, "exhausted-no-english"],
    };
}
