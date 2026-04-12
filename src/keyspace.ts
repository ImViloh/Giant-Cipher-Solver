/** Shared [a-zA-Z0-9] key enumeration for brute-force workers and main thread. */

export const ALPHANUM62 =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

const N62 = ALPHANUM62.length;

export function keyFromIndex(len: number, idx: number): string {
  let s = "";
  let t = idx;
  for (let p = 0; p < len; p++) {
    s += ALPHANUM62[t % N62]!;
    t = Math.floor(t / N62);
  }
  return s;
}

export function pow62(len: number): number {
  let p = 1;
  for (let i = 0; i < len; i++) p *= N62;
  return p;
}
