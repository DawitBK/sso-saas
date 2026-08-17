// Cross-validates the IdP's TOTP against RFC 6238: an independent HOTP
// implementation (written from the RFC pseudocode) is first checked against the
// RFC's official SHA-1 test vectors, then used to generate codes that the IdP's
// verifyTotp must accept.
import crypto from 'node:crypto';
import { generateTotpSecret, verifyTotp } from '../src/auth/totp.ts';

// Independent HOTP (RFC 4226 §5.3), SHA-1.
function hotpIndependent(secretBytes, counter, digits) {
  const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) { buf[i] = counter & 0xff; counter = Math.floor(counter / 256); }
  const h = crypto.createHmac('sha1', secretBytes).update(buf).digest();
  const o = h[19] & 0xf;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

// RFC 6238 Appendix B vectors (SHA-1, secret = ASCII "12345678901234567890", 8 digits).
const rfcSecret = Buffer.from('12345678901234567890', 'ascii');
const vectors = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1234567890, '89005924'],
  [20000000000, '65353130'],
];
let vectorsOk = true;
for (const [t, expected] of vectors) {
  const got = hotpIndependent(rfcSecret, Math.floor(t / 30), 8);
  if (got !== expected) { vectorsOk = false; console.log(`RFC vector T=${t}: got ${got}, want ${expected} ❌`); }
}
console.log('Independent impl matches RFC 6238 vectors:', vectorsOk ? 'YES ✅' : 'NO ❌');

//