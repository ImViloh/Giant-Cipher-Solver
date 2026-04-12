import { parentPort, workerData } from "node:worker_threads";
import { Buffer } from "node:buffer";
import { isFullyEnglishReadable } from "../englishReadability.js";
import { keyFromIndex } from "../keyspace.js";
import { xorBuffer } from "../transforms.js";
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
    const buf = Buffer.from(data.decoded.buffer, data.decoded.byteOffset, data.decoded.byteLength);
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
        const x = xorBuffer(buf, key);
        const text = tryDecoded(x);
        tried++;
        sinceTick++;
        if (sinceTick >= PROGRESS_EVERY) {
            parentPort.postMessage({ type: "tick", delta: PROGRESS_EVERY });
            sinceTick = 0;
        }
        if (text) {
            if (sinceTick > 0) {
                parentPort.postMessage({ type: "tick", delta: sinceTick });
            }
            parentPort.postMessage({
                type: "done",
                hit: { key, text },
                tried,
                timedOut: false,
            });
            return;
        }
    }
    if (sinceTick > 0) {
        parentPort.postMessage({ type: "tick", delta: sinceTick });
    }
    parentPort.postMessage({ type: "done", hit: null, tried, timedOut: false });
}
run();
