export interface VigRangeWorkerData {
    cipherB64: string;
    mode: "vigenere-b64" | "beaufort-b64";
    keyLen: number;
    rangeStart: number;
    rangeEnd: number;
    deadline: number;
}
