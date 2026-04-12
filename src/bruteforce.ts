import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { cpus } from "node:os";
import {
  isFullyEnglishReadable,
  englishReadabilityRank,
} from "./englishReadability.js";
import { keyFromIndex, pow62 } from "./keyspace.js";
import {
  safeBase64Decode,
  vigenereBase64Decrypt,
  beaufortBase64Decrypt,
  xorBuffer,
} from "./transforms.js";
import { setBruteProgress } from "./bruteState.js";

export { ALPHANUM62 } from "./keyspace.js";

/** Minimum keyspace size before spawning worker threads (overhead not worth it below). */
const PARALLEL_MIN_KEYS = 8_192;

const TICK_XOR_VIG = 250_000;

/** `maxMs <= 0` means no time limit (practical infinity). */
export function bruteDeadline(t0: number, maxMs: number): number {
  if (maxMs <= 0) return Number.MAX_SAFE_INTEGER;
  return t0 + maxMs;
}

export function getWorkerThreadCount(): number {
  const raw = process.env.GIANT_THREADS;
  if (raw !== undefined && raw !== "") {
    const n = Number.parseInt(raw, 10);
    if (Number.isFinite(n) && n > 0) return Math.min(64, n);
    if (n === 0) return 1;
  }
  return Math.max(1, cpus().length);
}

const xorWorkerFile = fileURLToPath(
  new URL("./workers/xorRangeWorker.js", import.meta.url),
);
const vigWorkerFile = fileURLToPath(
  new URL("./workers/vigRangeWorker.js", import.meta.url),
);

function tryDecodedBuffer(buf: Buffer): string | null {
  const latin1 = buf.toString("latin1");
  if (isFullyEnglishReadable(latin1)) return latin1;
  try {
    const u = buf.toString("utf8");
    if (!/\uFFFD/.test(u) && isFullyEnglishReadable(u)) return u;
  } catch {
    /* ignore */
  }
  return null;
}

export interface BruteXorResult {
  key: string;
  text: string;
}

export interface BruteXorOutcome {
  hit: BruteXorResult | null;
  tried: number;
  timedOut: boolean;
}

interface XorWorkerDoneMsg {
  type: "done";
  hit: { key: string; text: string } | null;
  tried: number;
  timedOut: boolean;
}

function syncXorRange(
  decoded: Buffer,
  len: number,
  rangeStart: number,
  rangeEnd: number,
  deadline: number,
  cumulativeBefore: number,
): { hit: BruteXorResult | null; tried: number; timedOut: boolean } {
  let tried = 0;
  let sinceTick = 0;
  for (let i = rangeStart; i < rangeEnd; i++) {
    if (Date.now() > deadline) {
      return { hit: null, tried, timedOut: true };
    }
    const key = keyFromIndex(len, i);
    const x = xorBuffer(decoded, key);
    const text = tryDecodedBuffer(x);
    tried++;
    sinceTick++;
    if (sinceTick >= TICK_XOR_VIG) {
      setBruteProgress({
        phase: "xor",
        xorKeyLen: len,
        xorTried: cumulativeBefore + tried,
      });
      sinceTick = 0;
    }
    if (text) {
      setBruteProgress({
        phase: "xor",
        xorKeyLen: len,
        xorTried: cumulativeBefore + tried,
      });
      return { hit: { key, text }, tried, timedOut: false };
    }
  }
  setBruteProgress({
    phase: "xor",
    xorKeyLen: len,
    xorTried: cumulativeBefore + tried,
  });
  return { hit: null, tried, timedOut: false };
}

async function parallelXorRange(
  decoded: Buffer,
  len: number,
  total: number,
  deadline: number,
  cumulativeBefore: number,
): Promise<{ hit: BruteXorResult | null; tried: number; timedOut: boolean }> {
  const threads = getWorkerThreadCount();
  const chunk = Math.ceil(total / threads);
  const workers: Worker[] = [];
  let tickAcc = 0;

  function waitDone(w: Worker): Promise<XorWorkerDoneMsg> {
    return new Promise((resolve, reject) => {
      w.on("message", (msg: unknown) => {
        const m = msg as {
          type?: string;
          delta?: number;
          hit?: XorWorkerDoneMsg["hit"];
          tried?: number;
          timedOut?: boolean;
        };
        if (m.type === "tick" && typeof m.delta === "number") {
          tickAcc += m.delta;
          setBruteProgress({
            phase: "xor",
            xorKeyLen: len,
            xorTried: cumulativeBefore + tickAcc,
          });
        } else if (m.type === "done") {
          resolve({
            type: "done",
            hit: m.hit ?? null,
            tried: m.tried ?? 0,
            timedOut: m.timedOut ?? false,
          });
        }
      });
      w.once("error", reject);
    });
  }

  const promises: Promise<XorWorkerDoneMsg>[] = [];

  for (let t = 0; t < threads; t++) {
    const rangeStart = t * chunk;
    const rangeEnd = Math.min(total, rangeStart + chunk);
    if (rangeStart >= rangeEnd) continue;

    const w = new Worker(xorWorkerFile, {
      workerData: {
        decoded: new Uint8Array(decoded),
        keyLen: len,
        rangeStart,
        rangeEnd,
        deadline,
      },
    });
    workers.push(w);
    promises.push(waitDone(w));
  }

  const msgs = await Promise.all(promises);
  for (const w of workers) {
    void w.terminate();
  }

  let tried = 0;
  let hit: BruteXorResult | null = null;
  let timedOut = false;
  for (const m of msgs) {
    tried += m.tried;
    if (m.hit && !hit) hit = m.hit;
    if (m.timedOut) timedOut = true;
  }
  setBruteProgress({
    phase: "xor",
    xorKeyLen: len,
    xorTried: cumulativeBefore + tried,
  });
  return { hit, tried, timedOut };
}

/**
 * Enumerate every repeating XOR key over [a-zA-Z0-9] up to maxKeyLen.
 * Uses worker threads for large keyspaces per length.
 */
export async function bruteXorAlphanumeric(
  decoded: Buffer,
  maxKeyLen: number,
  maxMs: number,
  onProgress?: (phase: string, tried: number, keyLen: number) => void,
): Promise<BruteXorOutcome> {
  const t0 = Date.now();
  const deadline = bruteDeadline(t0, maxMs);
  let tried = 0;

  for (let len = 1; len <= maxKeyLen; len++) {
    if (Date.now() > deadline) {
      onProgress?.("xor-timeout", tried, len);
      return { hit: null, tried, timedOut: true };
    }

    setBruteProgress({
      phase: "xor",
      xorKeyLen: len,
      xorTried: tried,
    });

    const total = pow62(len);
    const useParallel =
      getWorkerThreadCount() > 1 && total >= PARALLEL_MIN_KEYS;

    let hit: BruteXorResult | null = null;
    let timedOut = false;
    let batchTried = 0;

    if (useParallel) {
      const r = await parallelXorRange(
        decoded,
        len,
        total,
        deadline,
        tried,
      );
      hit = r.hit;
      batchTried = r.tried;
      timedOut = r.timedOut;
    } else {
      const r = syncXorRange(
        decoded,
        len,
        0,
        total,
        deadline,
        tried,
      );
      hit = r.hit;
      batchTried = r.tried;
      timedOut = r.timedOut;
    }

    tried += batchTried;

    if (hit) {
      return { hit, tried, timedOut: false };
    }
    if (timedOut) {
      onProgress?.("xor-timeout", tried, len);
      return { hit: null, tried, timedOut: true };
    }

    onProgress?.("xor-done", tried, len);
  }

  onProgress?.("xor-done", tried, maxKeyLen);
  return { hit: null, tried, timedOut: false };
}

export interface BruteVigResult {
  key: string;
  text: string;
  mode: "vigenere-b64" | "beaufort-b64";
}

export interface BruteVigOutcome {
  hit: BruteVigResult | null;
  tried: number;
  timedOut: boolean;
}

interface VigWorkerDoneMsg {
  type: "done";
  hit: { key: string; text: string; mode: BruteVigResult["mode"] } | null;
  tried: number;
  timedOut: boolean;
}

function syncVigRange(
  cipherB64: string,
  mode: BruteVigResult["mode"],
  len: number,
  rangeStart: number,
  rangeEnd: number,
  deadline: number,
  cumulativeBefore: number,
): { hit: BruteVigResult | null; tried: number; timedOut: boolean } {
  const fn =
    mode === "vigenere-b64" ? vigenereBase64Decrypt : beaufortBase64Decrypt;
  let tried = 0;
  let sinceTick = 0;
  for (let i = rangeStart; i < rangeEnd; i++) {
    if (Date.now() > deadline) {
      return { hit: null, tried, timedOut: true };
    }
    const key = keyFromIndex(len, i);
    const b64Out = fn(cipherB64, key);
    const buf = safeBase64Decode(b64Out);
    tried++;
    sinceTick++;
    if (sinceTick >= TICK_XOR_VIG) {
      setBruteProgress({
        phase: "vig",
        vigMode: mode,
        vigKeyLen: len,
        vigTried: cumulativeBefore + tried,
      });
      sinceTick = 0;
    }
    if (!buf) continue;
    const text = tryDecodedBuffer(buf);
    if (text) {
      setBruteProgress({
        phase: "vig",
        vigMode: mode,
        vigKeyLen: len,
        vigTried: cumulativeBefore + tried,
      });
      return { hit: { key, text, mode }, tried, timedOut: false };
    }
  }
  setBruteProgress({
    phase: "vig",
    vigMode: mode,
    vigKeyLen: len,
    vigTried: cumulativeBefore + tried,
  });
  return { hit: null, tried, timedOut: false };
}

async function parallelVigRange(
  cipherB64: string,
  mode: BruteVigResult["mode"],
  len: number,
  total: number,
  deadline: number,
  cumulativeBefore: number,
): Promise<{ hit: BruteVigResult | null; tried: number; timedOut: boolean }> {
  const threads = getWorkerThreadCount();
  const chunk = Math.ceil(total / threads);
  const workers: Worker[] = [];
  let tickAcc = 0;

  function waitDone(w: Worker): Promise<VigWorkerDoneMsg> {
    return new Promise((resolve, reject) => {
      w.on("message", (msg: unknown) => {
        const m = msg as {
          type?: string;
          delta?: number;
          hit?: VigWorkerDoneMsg["hit"];
          tried?: number;
          timedOut?: boolean;
        };
        if (m.type === "tick" && typeof m.delta === "number") {
          tickAcc += m.delta;
          setBruteProgress({
            phase: "vig",
            vigMode: mode,
            vigKeyLen: len,
            vigTried: cumulativeBefore + tickAcc,
          });
        } else if (m.type === "done") {
          resolve({
            type: "done",
            hit: m.hit ?? null,
            tried: m.tried ?? 0,
            timedOut: m.timedOut ?? false,
          });
        }
      });
      w.once("error", reject);
    });
  }

  const promises: Promise<VigWorkerDoneMsg>[] = [];

  for (let t = 0; t < threads; t++) {
    const rangeStart = t * chunk;
    const rangeEnd = Math.min(total, rangeStart + chunk);
    if (rangeStart >= rangeEnd) continue;

    const w = new Worker(vigWorkerFile, {
      workerData: {
        cipherB64,
        mode,
        keyLen: len,
        rangeStart,
        rangeEnd,
        deadline,
      },
    });
    workers.push(w);
    promises.push(waitDone(w));
  }

  const msgs = await Promise.all(promises);
  for (const w of workers) {
    void w.terminate();
  }

  let tried = 0;
  let hit: BruteVigResult | null = null;
  let timedOut = false;
  for (const m of msgs) {
    tried += m.tried;
    if (m.hit && !hit) hit = m.hit;
    if (m.timedOut) timedOut = true;
  }
  setBruteProgress({
    phase: "vig",
    vigMode: mode,
    vigKeyLen: len,
    vigTried: cumulativeBefore + tried,
  });
  return { hit, tried, timedOut };
}

/**
 * Brute Vigenère / Beaufort on Base64 layer with alphanumeric keys.
 */
export async function bruteVigenereB64Alphanumeric(
  cipherB64: string,
  maxKeyLen: number,
  maxMs: number,
  onProgress?: (phase: string, tried: number) => void,
): Promise<BruteVigOutcome> {
  const t0 = Date.now();
  const deadline = bruteDeadline(t0, maxMs);
  let tried = 0;

  const modes: BruteVigResult["mode"][] = [
    "vigenere-b64",
    "beaufort-b64",
  ];

  for (const mode of modes) {
    for (let len = 1; len <= maxKeyLen; len++) {
      if (Date.now() > deadline) {
        onProgress?.(`${mode}-timeout`, tried);
        return { hit: null, tried, timedOut: true };
      }

      setBruteProgress({
        phase: "vig",
        vigMode: mode,
        vigKeyLen: len,
        vigTried: tried,
      });

      const total = pow62(len);
      const useParallel =
        getWorkerThreadCount() > 1 && total >= PARALLEL_MIN_KEYS;

      let hit: BruteVigResult | null = null;
      let timedOut = false;
      let batchTried = 0;

      if (useParallel) {
        const r = await parallelVigRange(
          cipherB64,
          mode,
          len,
          total,
          deadline,
          tried,
        );
        hit = r.hit;
        batchTried = r.tried;
        timedOut = r.timedOut;
      } else {
        const r = syncVigRange(
          cipherB64,
          mode,
          len,
          0,
          total,
          deadline,
          tried,
        );
        hit = r.hit;
        batchTried = r.tried;
        timedOut = r.timedOut;
      }

      tried += batchTried;

      if (hit) {
        return { hit, tried, timedOut: false };
      }
      if (timedOut) {
        onProgress?.(`${mode}-timeout`, tried);
        return { hit: null, tried, timedOut: true };
      }

      onProgress?.(mode, tried);
    }
  }

  onProgress?.("vig-done", tried);
  return { hit: null, tried, timedOut: false };
}

/** Best Latin-1 string by readability rank (for reporting when nothing passes). */
export function rankLatin1Text(text: string): number {
  return englishReadabilityRank(text);
}
