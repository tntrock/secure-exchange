import { createHmac } from "node:crypto";

// RFC 6238 TOTP: SHA-1, 30 s steps, 6 digits. The server accepts the previous, current and next step,
// but each step only once: a second code inside one window needs `at = Date.now() + 30_000`.
export function totp(secretBase32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretBase32.replace(/=+$/, "").toUpperCase()) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new Error(`bad base32 character ${ch}`);
    bits += v.toString(2).padStart(5, "0");
  }
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac("sha1", key).update(counter).digest();
  const off = h[h.length - 1] & 0xf;
  return ((h.readUInt32BE(off) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

// secretFromOtpauth returns the base32 secret of an otpauth:// URL.
export const secretFromOtpauth = (url: string): string => new URL(url).searchParams.get("secret") ?? "";
