/** Shared [a-zA-Z0-9] key enumeration for brute-force workers and main thread. */
export declare const ALPHANUM62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export declare function keyFromIndex(len: number, idx: number): string;
export declare function pow62(len: number): number;
