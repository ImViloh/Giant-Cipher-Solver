import { parentPort, workerData } from "node:worker_threads";
import { isFullyEnglishReadable } from "../englishReadability.js";
import { keyFromIndex } from "../keyspace.js";
import { beaufortBase64Decrypt, safeBase64Decode, vigenereBase64Decrypt, } from "../transforms.js";
function tryDecoded(buf) {
    const latin1 = buf.toString("latin1");
    if (isFullyEnglishReadable(latin1))
        return latin1;
    try {
        const u = buf.toString("utf8");
        if (!/\uFFFD/.test(u) && isFullyEnglishReadable(u))
            return u;
    }
    catch {
        /* ignore */
    }
    return null;
}
const PROGRESS_EVERY = 250_000;
function run() {
    const data = workerData;
    const fn = data.mode === "vigenere-b64"
        ? vigenereBase64Decrypt
        : beaufortBase64Decrypt;
    let tried = 0;
    let sinceTick = 0;
    for (let i = data.rangeStart; i < data.rangeEnd; i++) {
        if (Date.now() > data.deadline) {
            if (sinceTick > 0) {
                parentPort.postMessage({ type: "tick", delta: sinceTick });
            }
            parentPort.postMessage({
                type: "done",
                hit: null,
                tried,
                timedOut: true,
            });
            return;
        }
        const key = keyFromIndex(data.keyLen, i);
        const b64Out = fn(data.cipherB64, key);
        const buf = safeBase64Decode(b64Out);
        tried++;
        sinceTick++;
        if (sinceTick >= PROGRESS_EVERY) {
            parentPort.postMessage({ type: "tick", delta: PROGRESS_EVERY });
            sinceTick = 0;
        }
        if (!buf)
            continue;
        const text = tryDecoded(buf);
        if (text) {
            if (sinceTick > 0) {
                parentPort.postMessage({ type: "tick", delta: sinceTick });
            }
            parentPort.postMessage({
                type: "done",
                hit: { key, text, mode: data.mode },
                tried,
                timedOut: false,
            });
            return;
        }
    }
    if (sinceTick > 0) {
        parentPort.postMessage({ type: "tick", delta: sinceTick });
    }
    parentPort.postMessage({
        type: "done",
        hit: null,
        tried,
        timedOut: false,
    });
}
run();
