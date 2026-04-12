export interface XorRangeWorkerData {
    decoded: Uint8Array;
    keyLen: number;
    rangeStart: number;
    rangeEnd: number;
    deadline: number;
}
