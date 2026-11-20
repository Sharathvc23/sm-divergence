// Check a Corroboration Record without asking the site that issued it.
//
// Dependency-free ES module for modern browsers and Node 18+. A record verifies offline:
//
//   1. record_id is lowercase-hex SHA-256 over the canonical JSON (RFC 8785) of every member
//      except record_id and signature;
//   2. sweeper is a did:key, which *is* the Ed25519 public key (multicodec 0xed01, base58btc);
//   3. signature is base64 Ed25519 over the canonical JSON of every member except signature.
//
// Ed25519 goes through WebCrypto when the runtime has it and falls back to the bundled
// pure-JavaScript verifier otherwise.

import { verify as verifyEd25519Fallback } from "./ed25519.js";

export const ACCEPTED_VERSIONS = Object.freeze(["corroboration/0.1", "corroboration/0.2", "corroboration/0.3", "corroboration/0.4"]);
const PRE_ALG_VERSIONS = ["corroboration/0.1", "corroboration/0.2"];
const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785) for the values a record holds: strings, integers,
// booleans, null, arrays, objects. Keys sort by UTF-16 code unit, which is what
// Array.prototype.sort does; strings are written as JSON.stringify writes them.
// A record never holds a float, so one is refused rather than guessed at.

export function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("a record holds integers only");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
  }
  throw new TypeError(`${typeof value} cannot be canonicalized`);
}

// ---------------------------------------------------------------------------
// Encodings

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function fromBase58(text) {
  let n = 0n;
  for (const ch of text) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new TypeError("not base58");
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  for (; n > 0n; n >>= 8n) bytes.unshift(Number(n & 0xffn));
  for (const ch of text) {
    if (ch !== "1") break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

export function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** The 32-byte Ed25519 public key a did:key encodes, or null. */
export function publicKeyFromDidKey(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) return null;
  let raw;
  try {
    raw = fromBase58(did.slice("did:key:z".length));
  } catch {
    return null;
  }
  return raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01 ? raw.slice(2) : null;
}

// ---------------------------------------------------------------------------
// Hash and signature

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("this runtime has no WebCrypto (crypto.subtle); in a browser it needs a secure context");
  return s;
}

export async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await subtle().digest("SHA-256", bytes)));
}

async function verifyEd25519(signature, message, publicKey, forceFallback) {
  if (!forceFallback) {
    try {
      const key = await subtle().importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
      return await subtle().verify("Ed25519", key, signature, message);
    } catch {
      /* no Ed25519 in this WebCrypto: the fallback decides */
    }
  }
  return verifyEd25519Fallback(signature, message, publicKey);
}

// ---------------------------------------------------------------------------
// The record

/**
 * Verify a Corroboration Record.
 *
 * @param {object} record the parsed record
 * @param {{trustedSweeper?: string, forceFallback?: boolean}} [options]
 *   trustedSweeper: the did:key the record must be signed by.
 * @returns {Promise<{ok: boolean, why?: string, sweeper?: string, verdict?: string, recordId?: string}>}
 */
export async function verifyRecord(record, { trustedSweeper, forceFallback = false } = {}) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return { ok: false, why: "not a record object" };
  const { record_id: recordId, signature, sweeper, verdict } = record;
  const fail = (why) => ({ ok: false, why, sweeper, verdict, recordId });
  if (!ACCEPTED_VERSIONS.includes(record.version)) return fail(`unknown record version ${JSON.stringify(record.version)}`);
  if (typeof signature !== "string" || !signature || typeof recordId !== "string" || typeof sweeper !== "string") {
    return fail("record_id, signature or sweeper is missing");
  }
  if (trustedSweeper !== undefined && trustedSweeper !== null && sweeper !== trustedSweeper) return fail("signed by a different sweeper");

  const body = { ...record };
  delete body.record_id;
  delete body.signature;
  let digest;
  try {
    digest = await sha256Hex(encoder.encode(canonicalize(body)));
  } catch (error) {
    return fail(`the record holds a value that cannot be canonicalized: ${error.message}`);
  }
  if (digest !== recordId) return fail("the content no longer matches record_id");

  const publicKey = publicKeyFromDidKey(sweeper);
  if (!publicKey) return fail("sweeper is not an Ed25519 did:key");
  if (record.alg === undefined ? !PRE_ALG_VERSIONS.includes(record.version) : record.alg !== "EdDSA") {
    return fail("alg does not agree with the sweeper's key type");
  }

  let sig;
  try {
    sig = fromBase64(signature);
  } catch {
    return fail("malformed signature");
  }
  if (sig.length !== 64) return fail("malformed signature");
  const signed = { ...record };
  delete signed.signature;
  const good = await verifyEd25519(sig, encoder.encode(canonicalize(signed)), publicKey, forceFallback);
  return good ? { ok: true, sweeper, verdict, recordId } : fail("the signature doesn't match this record");
}
