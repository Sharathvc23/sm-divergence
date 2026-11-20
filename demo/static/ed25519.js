// Ed25519 signature verification in plain JavaScript (RFC 8032, section 5.1.7).
//
// This is the fallback for runtimes whose WebCrypto has no Ed25519 (older Safari,
// some embedded engines). It only verifies — there is no signing here — and it uses
// BigInt field arithmetic, so it is small and readable rather than fast: a single
// verification takes a few milliseconds. SHA-512 comes from WebCrypto, which every
// runtime has.

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function mod(a) {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function modpow(base, exp) {
  let result = 1n;
  base = mod(base);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base);
    base = mod(base * base);
    exp >>= 1n;
  }
  return result;
}

function invert(a) {
  return modpow(a, P - 2n);
}

const D = mod(-121665n * invert(121666n));
const SQRT_M1 = modpow(2n, (P - 1n) / 4n);

const B = {
  x: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  y: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
  z: 1n,
  t: 0n,
};
B.t = mod(B.x * B.y);

const IDENTITY = { x: 0n, y: 1n, z: 1n, t: 0n };

// Extended twisted Edwards coordinates (a = -1), unified addition: works for doubling too.
function add(p, q) {
  const a = mod((p.y - p.x) * (q.y - q.x));
  const b = mod((p.y + p.x) * (q.y + q.x));
  const c = mod(2n * p.t * q.t * D);
  const d = mod(2n * p.z * q.z);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return { x: mod(e * f), y: mod(g * h), t: mod(e * h), z: mod(f * g) };
}

function multiply(point, scalar) {
  let result = IDENTITY;
  let addend = point;
  while (scalar > 0n) {
    if (scalar & 1n) result = add(result, addend);
    addend = add(addend, addend);
    scalar >>= 1n;
  }
  return result;
}

function pointsEqual(p, q) {
  return mod(p.x * q.z - q.x * p.z) === 0n && mod(p.y * q.z - q.y * p.z) === 0n;
}

function littleEndianToBigInt(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

// Decode a 32-byte compressed point. Returns null when the bytes are not a point on the curve.
export function decodePoint(bytes) {
  if (bytes.length !== 32) return null;
  const sign = bytes[31] >> 7;
  const y = littleEndianToBigInt(bytes) & ((1n << 255n) - 1n);
  if (y >= P) return null;
  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const v3 = mod(v * v * v);
  const v7 = mod(v3 * v3 * v);
  let x = mod(u * v3 * modpow(u * v7, (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else if (vx2 !== u) return null;
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return { x, y, z: 1n, t: mod(x * y) };
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function sha512(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("this runtime has no WebCrypto digest; cannot compute SHA-512");
  return new Uint8Array(await subtle.digest("SHA-512", bytes));
}

/**
 * Verify an Ed25519 signature.
 * @param {Uint8Array} signature 64 bytes (R || S)
 * @param {Uint8Array} message the signed bytes
 * @param {Uint8Array} publicKey 32 bytes
 * @returns {Promise<boolean>}
 */
export async function verify(signature, message, publicKey) {
  if (!(signature instanceof Uint8Array) || !(publicKey instanceof Uint8Array) || !(message instanceof Uint8Array)) {
    throw new TypeError("signature, message and publicKey must be Uint8Array");
  }
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const A = decodePoint(publicKey);
  if (!A) return false;
  const rBytes = signature.subarray(0, 32);
  const R = decodePoint(rBytes);
  if (!R) return false;
  const S = littleEndianToBigInt(signature.subarray(32));
  if (S >= L) return false; // non-canonical S: reject, as RFC 8032 requires
  const k = littleEndianToBigInt(await sha512(concat(rBytes, publicKey, message))) % L;
  const left = multiply(B, S);
  const right = add(R, multiply(A, k));
  return pointsEqual(left, right);
}
