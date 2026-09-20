/* ------------------------------------------------------------------
   crypto.js — everything is encrypted here, before it reaches Firebase.
   Key:  PBKDF2-SHA256 (310k rounds) over the master key.
   Data: AES-GCM 256, fresh 12-byte IV per item.
   Needs a secure context (https:// or http://localhost).
------------------------------------------------------------------ */

const TE = new TextEncoder();
const TD = new TextDecoder();
export const KDF_ROUNDS = 310000;

export function randomBytes(n){
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function toB64(bytes){
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function fromB64(str){
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function isSecureEnough(){
  return typeof crypto !== 'undefined' && !!crypto.subtle;
}

/** Derive an AES-GCM key from the master key + stored salt. */
export async function deriveKey(masterKey, saltB64, rounds = KDF_ROUNDS){
  const base = await crypto.subtle.importKey(
    'raw', TE.encode(masterKey), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt: fromB64(saltB64), iterations: rounds, hash:'SHA-256' },
    base,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

export function newSalt(){ return toB64(randomBytes(16)); }

/** Encrypt any JSON-serialisable value → { iv, ct } (both base64). */
export async function seal(key, value){
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name:'AES-GCM', iv }, key, TE.encode(JSON.stringify(value))
  );
  return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

/** Decrypt a { iv, ct } blob back into its original value. */
export async function open(key, blob){
  if (!blob || !blob.iv || !blob.ct) throw new Error('Blob is missing or malformed');
  const pt = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.ct)
  );
  return JSON.parse(TD.decode(pt));
}

const CANARY = 'sentrix-vault-unlocked';

/** A small blob used to check a master key without touching real data. */
export async function makeVerifier(key){ return seal(key, CANARY); }

export async function checkVerifier(key, verifier){
  try { return (await open(key, verifier)) === CANARY; }
  catch { return false; }
}

/** 0–4 strength score with a short reason. */
export function scorePassword(pw){
  if (!pw) return { score:0, label:'—' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const bits = pw.length * (Math.log2(pool || 1));
  const repeated = /(.)\1{2,}/.test(pw);
  const adjusted = repeated ? bits * 0.8 : bits;
  if (adjusted < 40) return { score:1, label:'Weak — a fast machine guesses this' };
  if (adjusted < 60) return { score:2, label:'Fair — fine for low-stakes accounts' };
  if (adjusted < 90) return { score:3, label:'Strong — good for most accounts' };
  return { score:4, label:'Very strong — safe for email and banking' };
}
