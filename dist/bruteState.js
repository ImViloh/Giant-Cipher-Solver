/**
 * Live brute-force progress for SIGINT / SIGTERM reporting (and optional UI).
 * Updated from the main thread and worker tick messages.
 */
const snap = {
    phase: "idle",
    xorKeyLen: 0,
    xorTried: 0,
    vigMode: "",
    vigKeyLen: 0,
    vigTried: 0,
};
export function resetBruteProgress() {
    snap.phase = "idle";
    snap.xorKeyLen = 0;
    snap.xorTried = 0;
    snap.vigMode = "";
    snap.vigKeyLen = 0;
    snap.vigTried = 0;
}
export function setBruteProgress(p) {
    if (p.phase !== undefined)
        snap.phase = p.phase;
    if (p.xorKeyLen !== undefined)
        snap.xorKeyLen = p.xorKeyLen;
    if (p.xorTried !== undefined)
        snap.xorTried = p.xorTried;
    if (p.vigMode !== undefined)
        snap.vigMode = p.vigMode;
    if (p.vigKeyLen !== undefined)
        snap.vigKeyLen = p.vigKeyLen;
    if (p.vigTried !== undefined)
        snap.vigTried = p.vigTried;
}
export function getBruteProgressSnapshot() {
    return { ...snap };
}
