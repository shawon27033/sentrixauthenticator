/* ------------------------------------------------------------------
   totp.js — RFC 4648 Base32 + RFC 6238 TOTP.
   Produces the same codes as Google Authenticator, Authy, 1Password…
------------------------------------------------------------------ */

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input){
  const clean = String(input).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean) throw new Error('The secret key is empty');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean){
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`"${ch}" is not a valid Base32 character`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8){
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (!out.length) throw new Error('The secret key is too short');
  return new Uint8Array(out);
}

export function normaliseSecret(raw){
  const clean = String(raw).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  base32Decode(clean);          // throws if invalid
  return clean;
}

function hashName(algorithm){
  switch (String(algorithm || 'SHA1').toUpperCase().replace('-', '')){
    case 'SHA256': return 'SHA-256';
    case 'SHA512': return 'SHA-512';
    case 'SHA1':
    default:       return 'SHA-1';
  }
}

async function hmac(algorithm, keyBytes, msgBytes){
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name:'HMAC', hash: hashName(algorithm) }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, msgBytes));
}

function counterBytes(counter){
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 4294967296));
  view.setUint32(4, counter >>> 0);
  return new Uint8Array(buf);
}

/** Current code for an account. */
export async function generateCode(account, nowMs = Date.now()){
  const period = Number(account.period) || 30;
  const digits = Number(account.digits) || 6;
  const counter = Math.floor(nowMs / 1000 / period);
  const mac = await hmac(account.algorithm, base32Decode(account.secret), counterBytes(counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Seconds left before the code rolls over. */
export function secondsLeft(period = 30, nowMs = Date.now()){
  const p = Number(period) || 30;
  return p - Math.floor(nowMs / 1000) % p;
}

/** Parse otpauth://totp/Issuer:name?secret=…&issuer=…&digits=…&period=…&algorithm=… */
export function parseOtpAuth(uri){
  const text = String(uri).trim();
  if (!/^otpauth:\/\//i.test(text)) throw new Error('That is not an otpauth:// link');

  const url = new URL(text);
  const kind = (url.host || url.hostname).toLowerCase();
  if (kind === 'hotp') throw new Error('Counter-based (HOTP) codes are not supported yet');
  if (kind && kind !== 'totp') throw new Error(`Unsupported code type: ${kind}`);

  let label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  let issuer = url.searchParams.get('issuer') || '';
  if (label.includes(':')){
    const [first, ...rest] = label.split(':');
    if (!issuer) issuer = first.trim();
    label = rest.join(':').trim();
  }

  const secret = normaliseSecret(url.searchParams.get('secret') || '');
  const digits = Math.min(Math.max(parseInt(url.searchParams.get('digits') || '6', 10) || 6, 6), 8);
  const period = Math.max(parseInt(url.searchParams.get('period') || '30', 10) || 30, 5);
  const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');

  return {
    label: label || issuer || 'Account',
    issuer: issuer || '',
    secret, digits, period, algorithm
  };
}

/** Rebuild an otpauth:// link, for export or re-scanning elsewhere. */
export function toOtpAuth(account){
  const label = account.issuer
    ? `${encodeURIComponent(account.issuer)}:${encodeURIComponent(account.label)}`
    : encodeURIComponent(account.label);
  const params = new URLSearchParams({
    secret: account.secret,
    digits: String(account.digits || 6),
    period: String(account.period || 30),
    algorithm: account.algorithm || 'SHA1'
  });
  if (account.issuer) params.set('issuer', account.issuer);
  return `otpauth://totp/${label}?${params.toString()}`;
}
