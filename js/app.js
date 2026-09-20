/* ------------------------------------------------------------------
   app.js — Sentrix Authenticator
   Codes and passwords live in Firestore, encrypted with the master key.
   Nothing sensitive is written to localStorage.
------------------------------------------------------------------ */

import {
  auth, observeAuthState, registerUser, loginUser, logoutUser, loginWithGoogle,
  finishRedirectLogin, resetPassword, setRemember, getProfile, saveProfile, saveSettings,
  saveKeyMaterial, uploadAvatar, watchCollection, addItem, updateItem,
  deleteItem, bulkWrite, deleteAll
} from './firebase.js';

import {
  deriveKey, newSalt, seal, open as unseal, makeVerifier, checkVerifier,
  isSecureEnough, scorePassword, KDF_ROUNDS
} from './crypto.js';

import { generateCode, secondsLeft, parseOtpAuth, normaliseSecret, toOtpAuth } from './totp.js';

/* ═══════════════ state ═══════════════ */

const state = {
  uid: null, preview: false, key: null, profile: null,
  settings: { theme:'light', accent:'iris', autolock:5, privacy:false },
  vault: [], totp: [],
  filter: 'all', search: '', totpSearch: '',
  revealed: new Set(), shown: new Set(),
  unsubs: [], cropper: null,
  scanning: false, scanStream: null,
  tick: null, idleTimer: null,
  lastCodes: new Map(),
  demo: null
};

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

const SCREEN_TITLES = {
  auth:      ['Authenticator', 'Two-factor codes'],
  vault:     ['Passwords', 'Your saved sign-ins'],
  generator: ['Generator', 'Build a password'],
  profile:   ['Profile', 'Account details'],
  settings:  ['Settings', 'Preferences']
};

/* A stable colour per service, so the same account always looks the same. */
const MONO_COLORS = ['#4B3FD6','#0E9E93','#D9385F','#B4801A','#2563C9',
                     '#7A35C9','#0E8F5E','#C2410C','#0F766E','#BE1E63'];
function monoColor(text){
  let h = 0;
  for (let i = 0; i < String(text).length; i++) h = (h * 31 + String(text).charCodeAt(i)) >>> 0;
  return MONO_COLORS[h % MONO_COLORS.length];
}
function initials(text){
  const parts = String(text || '?').trim().split(/[\s._@-]+/).filter(Boolean);
  return ((parts[0]?.[0] || '?') + (parts[1]?.[0] || '')).toUpperCase();
}

/* ═══════════════ small UI helpers ═══════════════ */

function toast(message, kind = 'ok'){
  const icons = { ok:'fa-circle-check', err:'fa-circle-exclamation', info:'fa-circle-info' };
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<i class="fa-solid ${icons[kind] || icons.ok}"></i><span>${esc(message)}</span>`;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 240); }, 2700);
}

const expand   = (el) => el.classList.add('open');
const collapse = (el) => el.classList.remove('open');
const setOpen  = (el, on) => el.classList.toggle('open', on);

function loading(btn, on, busyLabel){
  btn.classList.toggle('loading', on);
  btn.disabled = on;
  if (busyLabel && on) btn.dataset.busy = busyLabel;
}

function openSheet(id){
  $('#' + id).classList.remove('hidden');
  $('#fab')?.classList.add('away');
  const first = $('#' + id).querySelector('input:not([type=hidden]):not([hidden]), select, textarea');
  if (first && window.innerWidth > 900) setTimeout(() => first.focus(), 140);
}
function closeSheet(id){
  $('#' + id).classList.add('hidden');
  $('#fab')?.classList.remove('away');
  if (id === 'totp-sheet') stopScanner();
  if (id === 'crop-sheet' && state.cropper){ state.cropper.destroy(); state.cropper = null; }
}
const closeAllSheets = () => $$('.sheet-root').forEach(s => closeSheet(s.id));

function confirmAction(title, body, okLabel = 'Confirm'){
  return new Promise(resolve => {
    $('#confirm-title').textContent = title;
    $('#confirm-body').textContent = body;
    const ok = $('#confirm-ok');
    ok.textContent = okLabel;
    const finish = (answer) => {
      closeSheet('confirm-sheet');
      ok.removeEventListener('click', yes);
      $('#confirm-sheet').removeEventListener('click', maybeNo);
      resolve(answer);
    };
    const yes = () => finish(true);
    const maybeNo = (e) => { if (e.target.closest('[data-close]')) finish(false); };
    ok.addEventListener('click', yes);
    $('#confirm-sheet').addEventListener('click', maybeNo);
    openSheet('confirm-sheet');
  });
}

async function copyText(text, label = 'Copied'){
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch {}
    ta.remove();
  }
  toast(label);
  if (navigator.vibrate) navigator.vibrate(8);
}

function setSync(status){
  const pill = $('#sync-pill');
  if (!pill) return;
  pill.classList.toggle('busy', status === 'saving');
  pill.classList.toggle('off', status === 'offline');
  $('#sync-text').textContent = status === 'saving' ? 'Saving' : status === 'offline' ? 'Offline' : 'Synced';
  pill.querySelector('i').className = status === 'saving'
    ? 'fa-solid fa-rotate' : status === 'offline' ? 'fa-solid fa-cloud-slash' : 'fa-solid fa-cloud';
}

function friendlyError(err){
  const code = err?.code || '';
  // A rejected API key never reaches the sign-in logic, so say what to fix.
  if (code.startsWith('auth/api-key') || code === 'auth/invalid-api-key')
    return 'Firebase rejected the apiKey. Copy a fresh config from Project settings, and make sure the key allows the Identity Toolkit API.';
  if (code === 'auth/app-not-authorized' || code.startsWith('auth/requests-from-'))
    return 'This domain is not allowed to use that API key. Add it under Authorized domains and to the key\'s referrer list.';
  if (code === 'auth/configuration-not-found')
    return 'Email/Password sign-in is off. Turn it on in Firebase → Authentication → Sign-in method.';
  const map = {
    'auth/invalid-credential': 'That email and password do not match an account.',
    'auth/wrong-password': 'That password is not right.',
    'auth/user-not-found': 'No account uses that email yet.',
    'auth/email-already-in-use': 'That email already has an account. Try signing in.',
    'auth/weak-password': 'Pick a password of at least 6 characters.',
    'auth/invalid-email': 'Check the email address.',
    'auth/network-request-failed': 'No connection to Firebase. Check the network.',
    'auth/too-many-requests': 'Too many attempts. Wait a minute and try again.',
    'auth/popup-closed-by-user': 'The Google window closed before sign-in finished.',
    'auth/unauthorized-domain': 'Add this domain under Firebase → Authentication → Settings → Authorized domains.',
    'auth/operation-not-allowed': 'Turn on Google sign-in in Firebase → Authentication → Sign-in method.',
    'permission-denied': 'Firestore rules blocked that. Publish the rules from firestore.rules.'
  };
  return map[code] || err?.message || 'Something went wrong.';
}

/* ═══════════════ theme + settings ═══════════════ */

function applySettings(){
  const html = document.documentElement;
  html.dataset.theme = state.settings.theme || 'light';
  html.dataset.accent = state.settings.accent || 'iris';
  $('meta[name=theme-color]').setAttribute('content', state.settings.theme === 'dark' ? '#0D0F17' : '#F4F5F9');

  $$('#theme-seg button').forEach(b => b.classList.toggle('active', b.dataset.themeVal === state.settings.theme));
  $$('#accent-swatches button').forEach(b => b.classList.toggle('on', b.dataset.accentVal === state.settings.accent));
  $('#autolock-select').value = String(state.settings.autolock ?? 5);
  $('#privacy-toggle').checked = !!state.settings.privacy;
  paintMaskToggle();
  resetIdleTimer();
}

async function persistSettings(){
  applySettings();
  if (state.preview || !state.uid) return;
  try { await saveSettings(state.uid, state.settings); } catch {}
}

function paintMaskToggle(){
  const btn = $('#mask-toggle');
  const on = !!state.settings.privacy;
  btn.classList.toggle('on', on);
  btn.innerHTML = on
    ? '<i class="fa-regular fa-eye"></i> Show codes'
    : '<i class="fa-regular fa-eye-slash"></i> Hide codes';
}

/* ═══════════════ navigation ═══════════════ */

function goTo(tab){
  $$('.tab-content').forEach(s => s.classList.toggle('active', s.id === `tab-${tab}`));
  $$('.nav-item').forEach(i => i.classList.toggle('active', i.dataset.tab === tab));
  $$('.tab-btn').forEach(i => i.classList.toggle('active', i.dataset.tab === tab));

  const [title, sub] = SCREEN_TITLES[tab] || SCREEN_TITLES.auth;
  $('#m-screen-title').textContent = title;
  $('#m-screen-sub').textContent = sub;
  $('#fab').style.display = (tab === 'auth' || tab === 'vault') ? '' : 'none';
  moveRail();
  $('#content-area').scrollTop = 0;
}

function moveRail(){
  const active = $('.nav-item.active');
  const rail = $('#rail-indicator');
  if (!active || !rail) return;
  const sidebar = $('.sidebar').getBoundingClientRect();
  const item = active.getBoundingClientRect();
  if (!item.height) return;
  rail.style.height = `${item.height}px`;
  rail.style.setProperty('--rail-y', `${item.top - sidebar.top - 16}px`);
}

const show = (which) => {
  $('#auth-screen').classList.toggle('hidden', which !== 'auth');
  $('#key-screen').classList.toggle('hidden', which !== 'key');
  $('#app-window').classList.toggle('hidden', which !== 'app');
  if (which === 'app') requestAnimationFrame(moveRail);
};

/* ═══════════════ sign in / sign up ═══════════════ */

let signUpMode = false;

function setAuthMode(signUp, animate = false){
  signUpMode = signUp;
  setOpen($('#signup-fields'), signUp);
  $('#auth-title').textContent = signUp ? 'Create your account' : 'Welcome back';
  $('#auth-sub').textContent = signUp
    ? 'One account, every device — your codes follow you.'
    : 'Sign in to reach your codes and passwords on this device.';
  $('#auth-submit-btn').querySelector('.btn-label').textContent = signUp ? 'Create account' : 'Sign in';
  $('#toggle-text').textContent = signUp ? 'Already have an account?' : 'New to Sentrix?';
  $('#toggle-btn').textContent = signUp ? 'Sign in' : 'Create an account';
  $('#auth-password').autocomplete = signUp ? 'new-password' : 'current-password';
  $('#auth-password').placeholder = signUp ? 'At least 6 characters' : 'Your password';

  if (animate){
    const inner = $('.auth-inner');
    inner.classList.remove('replay'); void inner.offsetWidth; inner.classList.add('replay');
  }
}

async function handleAuthSubmit(e){
  e.preventDefault();
  const btn = $('#auth-submit-btn');
  const email = $('#auth-email').value.trim();
  const password = $('#auth-password').value;
  loading(btn, true);
  try {
    await setRemember($('#remember-me').checked);
    if (signUpMode){
      const first = $('#auth-fname').value.trim();
      const last  = $('#auth-lname').value.trim();
      if (!first) throw new Error('Add your first name so the app can greet you.');
      const cred = await registerUser(email, password);
      await saveProfile(cred.user.uid, {
        firstName: first, lastName: last, email, photoUrl: '', createdAt: Date.now()
      });
      toast('Account created');
    } else {
      await loginUser(email, password);
    }
  } catch (err){
    toast(friendlyError(err), 'err');
    const card = $('.auth-inner');
    card.classList.add('shake');
    setTimeout(() => card.classList.remove('shake'), 420);
  } finally {
    loading(btn, false);
  }
}

/* ═══════════════ master key ═══════════════ */

let keyMode = 'unlock';   // unlock | create | rotate

function showKeyScreen(mode){
  keyMode = mode;
  const creating = mode !== 'unlock';
  $('#key-title').textContent = mode === 'rotate' ? 'Choose a new master key'
                             : creating ? 'Create your master key' : 'Unlock your vault';
  $('#key-sub').textContent = creating
    ? 'This key encrypts everything before it is sent to Firebase.'
    : 'Your master key decrypts your data on this device.';
  setOpen($('#key-confirm-field'), creating);
  $('#key-warning').classList.toggle('hidden', !creating);
  $('#key-submit').querySelector('.btn-label').textContent = creating ? 'Create key' : 'Unlock';
  $('#key-input').value = ''; $('#key-confirm').value = '';
  $('#key-signout').classList.toggle('hidden', mode === 'rotate');
  show('key');
  setTimeout(() => $('#key-input').focus(), 220);
}

async function handleKeySubmit(e){
  e.preventDefault();
  const pass = $('#key-input').value;
  const btn = $('#key-submit');
  const fail = (msg) => {
    toast(msg, 'err');
    $('#key-card').classList.add('shake');
    setTimeout(() => $('#key-card').classList.remove('shake'), 420);
  };

  if (keyMode === 'unlock'){
    loading(btn, true);
    try {
      const kdf = state.profile.kdf;
      const key = await deriveKey(pass, kdf.salt, kdf.rounds || KDF_ROUNDS);
      if (!(await checkVerifier(key, state.profile.verifier))) return fail('That master key does not match.');
      state.key = key;
      await enterApp();
    } catch (err){ fail(friendlyError(err)); }
    finally { loading(btn, false); }
    return;
  }

  if (pass.length < 8) return fail('Use at least 8 characters.');
  if (pass !== $('#key-confirm').value) return fail('The two keys are different.');

  loading(btn, true);
  try {
    const salt = newSalt();
    const key = await deriveKey(pass, salt, KDF_ROUNDS);
    const verifier = await makeVerifier(key);

    if (keyMode === 'rotate'){
      for (const kind of ['vault','totp']){
        const rows = [];
        for (const item of state[kind]){
          const { id, accType, broken, ...fields } = item;
          rows.push({ id, data: { blob: await seal(key, fields), ...(accType ? { accType } : {}) } });
        }
        if (rows.length) await bulkWrite(state.uid, kind, rows);
      }
    }

    await saveKeyMaterial(state.uid, { salt, rounds: KDF_ROUNDS, algo:'PBKDF2-SHA256' }, verifier);
    state.profile = { ...state.profile, kdf:{ salt, rounds: KDF_ROUNDS }, verifier };
    state.key = key;
    toast(keyMode === 'rotate' ? 'Master key changed' : 'Master key created');
    await enterApp();
  } catch (err){ fail(friendlyError(err)); }
  finally { loading(btn, false); }
}

function lockVault(){
  state.key = null;
  state.vault = []; state.totp = [];
  state.revealed.clear(); state.shown.clear(); state.lastCodes.clear();
  state.unsubs.forEach(fn => { try { fn(); } catch {} });
  state.unsubs = [];
  stopTicker();
  if (state.preview) return signOutNow();
  showKeyScreen('unlock');
}

function resetIdleTimer(){
  clearTimeout(state.idleTimer);
  const minutes = Number(state.settings.autolock || 0);
  if (!minutes || !state.key || state.preview) return;
  state.idleTimer = setTimeout(() => { lockVault(); toast('Vault locked after inactivity', 'info'); }, minutes * 60000);
}

/* ═══════════════ entering the app ═══════════════ */

async function enterApp(){
  stopDemoTicker();
  show('app');
  goTo('auth');
  renderProfile();
  startWatchers();
  startTicker();
  resetIdleTimer();
}

function startWatchers(){
  if (state.preview){ renderVault(); renderTotp(); renderProfile(); return; }
  state.unsubs.forEach(fn => { try { fn(); } catch {} });
  state.unsubs = [];

  state.unsubs.push(watchCollection(state.uid, 'vault', async (docs) => {
    state.vault = await decryptRows(docs);
    renderVault(); renderProfile(); setSync('idle');
  }, () => { setSync('offline'); }));

  state.unsubs.push(watchCollection(state.uid, 'totp', async (docs) => {
    state.totp = await decryptRows(docs);
    renderTotp(); renderProfile(); setSync('idle');
  }, () => { setSync('offline'); }));
}

async function decryptRows(docs){
  const out = [];
  for (const d of docs){
    try {
      const fields = await unseal(state.key, d.blob);
      out.push({ id: d.id, accType: d.accType || fields.accType || 'Other', ...fields });
    } catch {
      out.push({ id: d.id, accType: d.accType || 'Other', broken: true,
                 platformName: 'Could not decrypt', label: 'Could not decrypt', username: '—' });
    }
  }
  return out;
}

/* ═══════════════ authenticator ═══════════════ */

function visibleTotp(){
  const q = state.totpSearch.toLowerCase();
  if (!q) return state.totp;
  return state.totp.filter(a => `${a.issuer} ${a.label}`.toLowerCase().includes(q));
}

function renderTotp(){
  const list = $('#totp-list');
  const rows = visibleTotp();

  if (!rows.length){
    list.innerHTML = state.totp.length
      ? `<div class="empty"><i class="fa-solid fa-magnifying-glass"></i><strong>No matches</strong>Try another name.</div>`
      : `<div class="empty"><i class="fa-solid fa-stopwatch"></i>
           <strong>Add your first 2FA account</strong>
           Turn on two-factor sign-in at any website, then scan the QR code it shows you.
           <button class="btn btn-primary" data-empty="totp"><i class="fa-solid fa-qrcode"></i> Scan a QR code</button>
         </div>`;
    return;
  }

  list.innerHTML = rows.map((a, i) => {
    const title = a.issuer || a.label;
    return `
    <article class="code-card" style="--i:${i}; --mono-c:${monoColor(title)}" data-id="${esc(a.id)}">
      <div class="code-mono">${esc(initials(title))}</div>
      <div class="code-head">
        <strong>${esc(title)}</strong>
        <span>${esc(a.issuer ? a.label : 'Authenticator account')}</span>
      </div>
      <div class="code-value" data-code title="Tap to copy">······</div>
      <div class="code-ring" data-ring>
        <svg viewBox="0 0 50 50"><circle class="track" cx="25" cy="25" r="21"/>
        <circle class="prog" cx="25" cy="25" r="21" stroke-dasharray="131.95" stroke-dashoffset="0"/></svg>
        <b data-left>–</b>
      </div>
      <div class="code-acts">
        <button class="icon-btn" data-act="copy-code" title="Copy code"><i class="fa-regular fa-copy"></i></button>
        <button class="icon-btn" data-act="copy-uri" title="Copy setup link"><i class="fa-solid fa-link"></i></button>
        <button class="icon-btn" data-act="remove-totp" title="Remove"><i class="fa-regular fa-trash-can"></i></button>
      </div>
    </article>`;
  }).join('');

  tickCodes(true);
}

function startTicker(){ stopTicker(); state.tick = setInterval(() => tickCodes(false), 1000); }
function stopTicker(){ if (state.tick) clearInterval(state.tick); state.tick = null; }

async function tickCodes(force){
  const cards = $$('#totp-list .code-card');
  if (!cards.length) return;
  const now = Date.now();

  for (const card of cards){
    const account = state.totp.find(a => a.id === card.dataset.id);
    if (!account) continue;

    const period = Number(account.period) || 30;
    const left = secondsLeft(period, now);
    const ring = card.querySelector('[data-ring]');
    const prog = card.querySelector('.prog');
    const codeEl = card.querySelector('[data-code]');

    card.querySelector('[data-left]').textContent = left;
    prog.style.strokeDashoffset = (131.95 * (1 - left / period)).toFixed(2);
    ring.classList.toggle('expiring', left <= 5);
    codeEl.classList.toggle('expiring', left <= 5);

    const slot = Math.floor(now / 1000 / period);
    const cached = state.lastCodes.get(account.id);
    if (force || !cached || cached.slot !== slot){
      let code = '------';
      try { code = await generateCode(account, now); } catch { code = 'invalid'; }
      state.lastCodes.set(account.id, { slot, code });
      if (cached && cached.slot !== slot){
        codeEl.classList.remove('flip'); void codeEl.offsetWidth; codeEl.classList.add('flip');
      }
    }

    const value = state.lastCodes.get(account.id).code;
    const hide = state.settings.privacy && !state.shown.has(account.id);
    codeEl.classList.toggle('masked', hide);
    codeEl.textContent = hide ? '•'.repeat(value.length) : value.replace(/(.{3})(?=.)/g, '$1 ');
  }
}

async function addTotpAccount(account){
  const clean = {
    label: account.label || 'Account',
    issuer: account.issuer || '',
    secret: normaliseSecret(account.secret),
    digits: Number(account.digits) || 6,
    period: Number(account.period) || 30,
    algorithm: (account.algorithm || 'SHA1').toUpperCase()
  };
  if (state.totp.some(a => a.secret === clean.secret)){
    toast('That account is already here.', 'info');
    return false;
  }
  await generateCode(clean);   // throws early if the secret is unusable

  if (state.preview){
    state.totp.unshift({ id: 'p' + Date.now(), ...clean });
    renderTotp();
  } else {
    setSync('saving');
    await addItem(state.uid, 'totp', { blob: await seal(state.key, clean) });
  }
  toast(`${clean.issuer || clean.label} added`);
  return true;
}

function openTotpSheet(){
  clearTotpForm();
  $$('#totp-mode button').forEach(b => b.classList.toggle('active', b.dataset.mode === 'scan'));
  $('#totp-scan').classList.remove('hidden');
  $('#totp-image').classList.add('hidden');
  $('#totp-manual').classList.add('hidden');
  $('#save-totp').classList.add('hidden');
  openSheet('totp-sheet');
}

function clearTotpForm(){
  $('#totp-label').value = ''; $('#totp-issuer').value = ''; $('#totp-secret').value = '';
  $('#totp-digits').value = '6'; $('#totp-period').value = '30'; $('#totp-algo').value = 'SHA1';
}

async function saveTotpFromForm(){
  try {
    const ok = await addTotpAccount({
      label:  $('#totp-label').value.trim() || $('#totp-issuer').value.trim(),
      issuer: $('#totp-issuer').value.trim(),
      secret: $('#totp-secret').value.trim(),
      digits: $('#totp-digits').value,
      period: $('#totp-period').value,
      algorithm: $('#totp-algo').value
    });
    if (ok){ clearTotpForm(); closeSheet('totp-sheet'); }
  } catch (err){ toast(err.message || 'That secret key is not valid.', 'err'); }
}

async function acceptScannedUri(text){
  try {
    const ok = await addTotpAccount(parseOtpAuth(text));
    if (ok){ stopScanner(); clearTotpForm(); closeSheet('totp-sheet'); }
  } catch (err){ toast(err.message || 'That QR code is not an authenticator code.', 'err'); }
}

/* ── QR scanning ── */

async function startScanner(){
  if (state.scanning) return stopScanner();
  if (typeof jsQR === 'undefined') return toast('The QR reader did not load. Use "Type key".', 'err');

  const video = $('#qr-video');
  try {
    state.scanStream = await navigator.mediaDevices.getUserMedia({ video:{ facingMode:'environment' }, audio:false });
  } catch {
    return toast('Camera access was refused. Use "QR image" or "Type key".', 'err');
  }

  video.srcObject = state.scanStream;
  await video.play();
  state.scanning = true;
  $('#scan-toggle').textContent = 'Stop camera';
  $('#scan-hint').textContent = 'Looking for a code…';

  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently:true });
  const loop = () => {
    if (!state.scanning) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA){
      canvas.width = video.videoWidth; canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const found = jsQR(img.data, img.width, img.height, { inversionAttempts:'dontInvert' });
      if (found?.data){ acceptScannedUri(found.data); return; }
    }
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
}

function stopScanner(){
  state.scanning = false;
  if (state.scanStream){ state.scanStream.getTracks().forEach(t => t.stop()); state.scanStream = null; }
  const video = $('#qr-video');
  if (video) video.srcObject = null;
  const btn = $('#scan-toggle');
  if (btn) btn.textContent = 'Start camera';
}

function readQrFromFile(file){
  if (typeof jsQR === 'undefined') return toast('The QR reader did not load.', 'err');
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      const scale = Math.min(1, 1400 / Math.max(img.width, img.height));
      canvas.width = Math.round(img.width * scale);
      canvas.height = Math.round(img.height * scale);
      const ctx = canvas.getContext('2d', { willReadFrequently:true });
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const found = jsQR(data.data, data.width, data.height);
      if (found?.data) acceptScannedUri(found.data);
      else toast('No QR code found in that image.', 'err');
    };
    img.onerror = () => toast('That image could not be read.', 'err');
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

/* ═══════════════ passwords ═══════════════ */

function visibleVault(){
  const q = state.search.toLowerCase();
  return state.vault.filter(item => {
    if (state.filter !== 'all' && item.accType !== state.filter) return false;
    if (!q) return true;
    return [item.platformName, item.username, item.accType, item.note, item.url]
      .some(v => String(v || '').toLowerCase().includes(q));
  });
}

function renderFilters(){
  const types = [...new Set(state.vault.map(i => i.accType).filter(Boolean))].sort();
  $('#type-filters').innerHTML = state.vault.length
    ? [['all','All'], ...types.map(t => [t,t])]
        .map(([v,l]) => `<button class="chip ${state.filter===v?'on':''}" data-filter="${esc(v)}">${esc(l)}</button>`).join('')
    : '';
}

function renderVault(){
  renderFilters();
  const list = $('#vault-list');
  const rows = visibleVault();

  if (!rows.length){
    list.innerHTML = state.vault.length
      ? `<div class="empty"><i class="fa-solid fa-magnifying-glass"></i><strong>No matches</strong>Try a different word, or clear the filter.</div>`
      : `<div class="empty"><i class="fa-regular fa-folder-open"></i>
           <strong>No passwords saved yet</strong>
           Add the first sign-in and it appears on every device you use.
           <button class="btn btn-primary" data-empty="cred"><i class="fa-solid fa-plus"></i> Add a password</button>
         </div>`;
    return;
  }

  list.innerHTML = rows.map((item, i) => {
    const name = item.platformName || item.accType || 'Untitled';
    const open = state.revealed.has(item.id);
    return `
    <article class="vault-row" style="--i:${i}; --mono-c:${monoColor(name)}" data-id="${esc(item.id)}">
      <div class="row-mark">${esc(initials(name))}</div>
      <div class="row-main">
        <strong>${esc(name)}</strong>
        <span>${esc(item.username || '—')}</span>
      </div>
      <div class="row-secret">
        <code>${open ? esc(item.password || '') : '••••••••••'}</code>
        <button class="icon-btn" data-act="peek" aria-label="Show password">
          <i class="fa-regular ${open ? 'fa-eye-slash' : 'fa-eye'}"></i></button>
      </div>
      <div class="row-acts">
        <button class="icon-btn" data-act="copy-user" title="Copy username"><i class="fa-regular fa-user"></i></button>
        <button class="icon-btn" data-act="copy-pass" title="Copy password"><i class="fa-regular fa-copy"></i></button>
        <button class="icon-btn" data-act="edit" title="Edit"><i class="fa-solid fa-pen"></i></button>
        <button class="icon-btn" data-act="delete" title="Delete"><i class="fa-regular fa-trash-can"></i></button>
      </div>
    </article>`;
  }).join('');
}

function openCredSheet(item = null){
  $('#cred-sheet-title').textContent = item ? 'Edit password' : 'Add password';
  $('#cred-id').value = item?.id || '';
  const select = $('#accTypeSelect');
  const known = [...select.options].some(o => o.value === (item?.accType || ''));
  select.value = item ? (known ? item.accType : 'Other') : '';
  setOpen($('#customPlatformDiv'), select.value === 'Other');
  $('#customPlatformInput').value = (select.value === 'Other') ? (item?.platformName || '') : '';
  $('#siteUser').value = item?.username || '';
  $('#sitePass').value = item?.password || '';
  $('#sitePass').type = 'password';
  $('#siteUrl').value  = item?.url || '';
  $('#siteNote').value = item?.note || '';
  openSheet('cred-sheet');
}

async function saveCredential(){
  const accType = $('#accTypeSelect').value;
  const custom  = $('#customPlatformInput').value.trim();
  const username = $('#siteUser').value.trim();
  const password = $('#sitePass').value;
  const id = $('#cred-id').value;

  if (!accType)  return toast('Choose a service first.', 'err');
  if (!username) return toast('Add the username or email.', 'err');
  if (!password) return toast('Add the password.', 'err');

  const fields = {
    accType,
    platformName: accType === 'Other' ? (custom || 'Other service') : accType,
    username, password,
    url: $('#siteUrl').value.trim(),
    note: $('#siteNote').value.trim()
  };

  if (state.preview){
    if (id) state.vault = state.vault.map(v => v.id === id ? { id, ...fields } : v);
    else state.vault.unshift({ id:'p' + Date.now(), ...fields });
    renderVault(); renderProfile(); closeSheet('cred-sheet');
    return toast('Saved for this session only', 'info');
  }

  setSync('saving');
  try {
    const payload = { accType, blob: await seal(state.key, fields) };
    if (id) await updateItem(state.uid, 'vault', id, payload);
    else    await addItem(state.uid, 'vault', payload);
    closeSheet('cred-sheet');
    toast(id ? 'Password updated' : 'Password saved');
  } catch (err){ setSync('offline'); toast(friendlyError(err), 'err'); }
}

/* ═══════════════ generator ═══════════════ */

const SETS = {
  lower:'abcdefghijklmnopqrstuvwxyz',
  upper:'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digit:'0123456789',
  symbol:'!@#$%^&*()_+-=[]{}|;:,.<>?'
};
const AMBIGUOUS = /[O0oIl1|]/g;

function makePassword(){
  const length = Number($('#passLength').value);
  const skip = $('#excAmbiguous').checked;
  const clean = (s) => skip ? s.replace(AMBIGUOUS, '') : s;

  const pools = [];
  if ($('#incLowercase').checked) pools.push(clean(SETS.lower));
  if ($('#incUppercase').checked) pools.push(clean(SETS.upper));
  if ($('#incNumbers').checked)   pools.push(clean(SETS.digit));
  if ($('#incSymbols').checked)   pools.push(clean(SETS.symbol));
  if (!pools.length){ toast('Turn on at least one character type.', 'err'); return null; }

  const all = pools.join('');
  const bytes = new Uint32Array(Math.max(length, pools.length));
  crypto.getRandomValues(bytes);

  const chars = pools.map((pool, i) => pool[bytes[i] % pool.length]);
  for (let i = chars.length; i < length; i++) chars.push(all[bytes[i] % all.length]);
  for (let i = chars.length - 1; i > 0; i--){
    const j = bytes[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, length).join('');
}

function showGenerated(pw){
  if (!pw) return;
  $('#generatedPassword').textContent = pw;
  const { score, label } = scorePassword(pw);
  const colours = ['var(--bad)','var(--bad)','var(--warn)','var(--ok)','var(--ok)'];
  $('#strength-fill').style.width = `${score * 25}%`;
  $('#strength-fill').style.background = colours[score];
  $('#strength-label').textContent = label;
}

/* ═══════════════ profile ═══════════════ */

function renderProfile(){
  const p = state.profile || {};
  const name = [p.firstName, p.lastName].filter(Boolean).join(' ')
            || (state.preview ? 'Preview user' : (p.email || 'Account'));
  const photo = p.photoUrl || 'images/avatar.svg';

  $('#user-display-name').textContent = p.firstName || (state.preview ? 'Preview' : 'Account');
  $('#main-profile-name').textContent = name;
  $('#main-profile-email').textContent = p.email || (state.preview ? 'nothing is saved' : '—');
  $('#user-avatar-img').src = photo;
  $('#m-avatar-img').src = photo;
  $('#main-profile-img').src = photo;
  $('#profile-tag').textContent = state.preview ? 'Preview mode' : 'Signed in';
  $('#stat-creds').textContent = state.vault.length;
  $('#stat-totp').textContent = state.totp.length;
  $('#stat-devices').textContent = state.preview ? 'None' : 'Cloud';
  $('#count-totp').textContent = state.totp.length;
  $('#count-vault').textContent = state.vault.length;
}

/* ═══════════════ backup ═══════════════ */

function exportBackup(){
  if (!state.vault.length && !state.totp.length) return toast('There is nothing to export yet.', 'info');
  const payload = {
    app:'Sentrix Authenticator', version:2, exportedAt: new Date().toISOString(),
    credentials: state.vault.map(({ id, broken, ...rest }) => rest),
    authenticators: state.totp.map(({ id, ...rest }) => ({ ...rest, otpauth: toOtpAuth(rest) }))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentrix-backup-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Backup downloaded — keep it offline');
}

async function importBackup(file){
  const text = await file.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { return toast('That file is not valid JSON.', 'err'); }

  const creds = Array.isArray(parsed) ? parsed : (parsed.credentials || []);
  const codes = Array.isArray(parsed) ? [] : (parsed.authenticators || []);
  if (!creds.length && !codes.length) return toast('No entries found in that file.', 'err');

  const ok = await confirmAction('Import this backup?',
    `${creds.length} passwords and ${codes.length} 2FA accounts will be added to your vault.`, 'Import');
  if (!ok) return;

  setSync('saving');
  try {
    const credRows = [];
    for (const c of creds){
      const fields = {
        accType: c.accType || 'Other',
        platformName: c.platformName || c.accType || 'Imported',
        username: c.username || c.user || '',
        password: c.password || c.pass || '',
        url: c.url || '', note: c.note || ''
      };
      credRows.push({ data: { accType: fields.accType, blob: await seal(state.key, fields) } });
    }
    const codeRows = [];
    for (const a of codes){
      try {
        const account = a.otpauth ? parseOtpAuth(a.otpauth) : {
          label:a.label, issuer:a.issuer, secret: normaliseSecret(a.secret),
          digits:a.digits, period:a.period, algorithm:a.algorithm
        };
        codeRows.push({ data: { blob: await seal(state.key, account) } });
      } catch {}
    }
    if (credRows.length) await bulkWrite(state.uid, 'vault', credRows);
    if (codeRows.length) await bulkWrite(state.uid, 'totp', codeRows);
    toast(`Imported ${credRows.length + codeRows.length} entries`);
  } catch (err){ toast(friendlyError(err), 'err'); }
}

/* ═══════════════ avatar ═══════════════ */

function handlePhotoPicked(e){
  const file = e.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    const target = $('#crop-image-target');
    target.src = ev.target.result;
    openSheet('crop-sheet');
    if (state.cropper) state.cropper.destroy();
    setTimeout(() => {
      state.cropper = new Cropper(target, { aspectRatio:1, viewMode:1, autoCropArea:.9, background:false });
    }, 240);
  };
  reader.readAsDataURL(file);
  e.target.value = '';
}

async function saveCroppedPhoto(){
  if (!state.cropper) return;
  const dataUrl = state.cropper.getCroppedCanvas({ width:320, height:320 }).toDataURL('image/jpeg', .88);
  $('#user-avatar-img').src = dataUrl;
  $('#m-avatar-img').src = dataUrl;
  $('#main-profile-img').src = dataUrl;
  closeSheet('crop-sheet');

  if (state.preview) return toast('Preview mode — the photo is not saved', 'info');
  setSync('saving');
  try {
    const url = await uploadAvatar(state.uid, dataUrl);
    await saveProfile(state.uid, { photoUrl: url });
    state.profile.photoUrl = url;
    setSync('idle');
    toast('Photo updated');
  } catch {
    setSync('offline');
    toast('Photo upload failed. Check Storage rules in Firebase.', 'err');
  }
}

/* ═══════════════ sign out / preview ═══════════════ */

async function signOutNow(){
  state.unsubs.forEach(fn => { try { fn(); } catch {} });
  state.unsubs = [];
  stopTicker(); stopScanner();
  Object.assign(state, { uid:null, key:null, profile:null, vault:[], totp:[], preview:false });
  state.lastCodes.clear();
  $('#preview-banner').classList.add('hidden');
  try { await logoutUser(); } catch {}
  show('auth');
  startDemoTicker();
}

function startPreview(){
  state.preview = true;
  state.uid = 'preview';
  state.profile = { firstName:'Preview', lastName:'', email:'nothing is saved' };
  state.totp = [
    { id:'d1', issuer:'GitHub',  label:'you@example.com', secret:'JBSWY3DPEHPK3PXP', digits:6, period:30, algorithm:'SHA1' },
    { id:'d2', issuer:'Google',  label:'you@gmail.com',   secret:'KRSXG5CTMVRXEZLU', digits:6, period:30, algorithm:'SHA1' },
    { id:'d3', issuer:'Binance', label:'trader-01',        secret:'MFRGGZDFMZTWQ2LK', digits:6, period:30, algorithm:'SHA1' }
  ];
  state.vault = [
    { id:'v1', accType:'Google', platformName:'Google', username:'you@gmail.com', password:'Tr0ub4dor&3xample', url:'', note:'' },
    { id:'v2', accType:'GitHub', platformName:'GitHub', username:'sentrix-dev',   password:'q7!Kv2mZp#Ld91',   url:'', note:'' }
  ];
  $('#preview-banner').classList.remove('hidden');
  applySettings();
  enterApp();
}

/* ═══════════════ live preview on the sign-in screen ═══════════════ */

const DEMO_ACCOUNTS = [
  { issuer:'GitHub',  label:'you@example.com', secret:'JBSWY3DPEHPK3PXP', digits:6, period:30, algorithm:'SHA1' },
  { issuer:'Google',  label:'you@gmail.com',   secret:'KRSXG5CTMVRXEZLU', digits:6, period:30, algorithm:'SHA1' },
  { issuer:'Dropbox', label:'work account',    secret:'MFRGGZDFMZTWQ2LK', digits:6, period:30, algorithm:'SHA1' }
];

function buildDemoDeck(){
  $('#preview-deck').innerHTML = DEMO_ACCOUNTS.map((a, i) => `
    <div class="pv-card" data-demo="${i}">
      <div class="pv-mono">${esc(initials(a.issuer))}</div>
      <div>
        <div class="pv-name">${esc(a.issuer)}</div>
        <div class="pv-sub">${esc(a.label)}</div>
        <div class="pv-code" data-demo-code>— — —</div>
      </div>
      <div class="pv-ring">
        <svg viewBox="0 0 40 40"><circle class="t" cx="20" cy="20" r="17"/>
        <circle class="p" cx="20" cy="20" r="17" stroke-dasharray="106.8" stroke-dashoffset="0"/></svg>
      </div>
    </div>`).join('');
}

async function tickDemo(){
  const now = Date.now();
  for (const card of $$('#preview-deck .pv-card')){
    const account = DEMO_ACCOUNTS[Number(card.dataset.demo)];
    const left = secondsLeft(account.period, now);
    card.querySelector('.p').style.strokeDashoffset = (106.8 * (1 - left / account.period)).toFixed(2);
    try {
      const code = await generateCode(account, now);
      card.querySelector('[data-demo-code]').textContent = code.replace(/(.{3})(?=.)/g, '$1 ');
    } catch {}
  }
}

function startDemoTicker(){
  stopDemoTicker();
  buildDemoDeck();
  tickDemo();
  state.demo = setInterval(tickDemo, 1000);
}
function stopDemoTicker(){ if (state.demo) clearInterval(state.demo); state.demo = null; }

/* ═══════════════ wiring ═══════════════ */

function wire(){
  $('#win-close').onclick = () => window.electronAPI?.close?.() ?? window.close();
  $('#win-min').onclick   = () => window.electronAPI?.minimize?.() ?? window.blur();
  $('#win-max').onclick   = () => {
    if (window.electronAPI?.maximize) return window.electronAPI.maximize();
    document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen();
  };

  /* auth */
  $('#auth-form').addEventListener('submit', handleAuthSubmit);
  $('#toggle-btn').onclick = () => setAuthMode(!signUpMode, true);
  $('#google-btn').onclick = async () => {
    const btn = $('#google-btn');
    btn.disabled = true;
    try { await setRemember($('#remember-me').checked); await loginWithGoogle(); }
    catch (err){ toast(friendlyError(err), 'err'); }
    finally { btn.disabled = false; }
  };
  $('#forgot-btn').onclick = async () => {
    const email = $('#auth-email').value.trim();
    if (!email) return toast('Type your email first, then tap this.', 'info');
    try { await resetPassword(email); toast('Reset link sent — check your inbox'); }
    catch (err){ toast(friendlyError(err), 'err'); }
  };
  $('#preview-btn').onclick = startPreview;
  $('#preview-exit').onclick = signOutNow;

  /* master key */
  $('#key-form').addEventListener('submit', handleKeySubmit);
  $('#key-signout').onclick = signOutNow;
  $('#lock-btn-desktop').onclick = lockVault;
  $('#lock-btn-mobile').onclick = lockVault;

  /* show / hide password fields */
  document.addEventListener('click', (e) => {
    const peek = e.target.closest('.peek');
    if (!peek) return;
    const input = $('#' + peek.dataset.peek);
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    peek.querySelector('i').className = showing ? 'fa-regular fa-eye' : 'fa-regular fa-eye-slash';
  });

  /* navigation */
  $$('.nav-item, .tab-btn').forEach(el => el.addEventListener('click', () => goTo(el.dataset.tab)));
  $$('[data-goto]').forEach(el => el.addEventListener('click', () => goTo(el.dataset.goto)));
  window.addEventListener('resize', moveRail);

  /* empty-state buttons */
  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-empty]');
    if (!b) return;
    b.dataset.empty === 'totp' ? openTotpSheet() : openCredSheet();
  });

  /* authenticator */
  $('#add-totp-btn').onclick = openTotpSheet;
  $('#save-totp').onclick = saveTotpFromForm;
  $('#totpSearch').addEventListener('input', (e) => { state.totpSearch = e.target.value; renderTotp(); });
  $('#mask-toggle').onclick = () => {
    state.settings.privacy = !state.settings.privacy;
    state.shown.clear();
    persistSettings();
    tickCodes(true);
  };
  $('#totp-mode').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-mode]');
    if (!btn) return;
    $$('#totp-mode button').forEach(b => b.classList.toggle('active', b === btn));
    $('#totp-scan').classList.toggle('hidden', btn.dataset.mode !== 'scan');
    $('#totp-image').classList.toggle('hidden', btn.dataset.mode !== 'image');
    $('#totp-manual').classList.toggle('hidden', btn.dataset.mode !== 'manual');
    $('#save-totp').classList.toggle('hidden', btn.dataset.mode !== 'manual');
    if (btn.dataset.mode !== 'scan') stopScanner();
  });
  $('#scan-toggle').onclick = startScanner;
  $('#qr-drop').addEventListener('click', () => $('#qr-file').click());
  $('#qr-file').addEventListener('change', (e) => { if (e.target.files[0]) readQrFromFile(e.target.files[0]); e.target.value=''; });

  $('#totp-list').addEventListener('click', async (e) => {
    const card = e.target.closest('.code-card');
    if (!card) return;
    const account = state.totp.find(a => a.id === card.dataset.id);
    if (!account) return;
    const btn = e.target.closest('[data-act]');

    const flash = () => {
      card.classList.remove('copied'); void card.offsetWidth; card.classList.add('copied');
      setTimeout(() => card.classList.remove('copied'), 700);
    };

    if (!btn){
      if (e.target.closest('[data-code]')){
        if (state.settings.privacy && !state.shown.has(account.id)){
          state.shown.add(account.id);
          tickCodes(true);
        } else {
          copyText(state.lastCodes.get(account.id)?.code || '', 'Code copied');
          flash();
        }
      }
      return;
    }

    switch (btn.dataset.act){
      case 'copy-code': copyText(state.lastCodes.get(account.id)?.code || '', 'Code copied'); flash(); break;
      case 'copy-uri':  copyText(toOtpAuth(account), 'Setup link copied'); break;
      case 'remove-totp': {
        const ok = await confirmAction('Remove this 2FA account?',
          `You will stop getting codes for ${account.issuer || account.label}. Make sure you have recovery codes saved first.`, 'Remove');
        if (!ok) return;
        if (state.preview){ state.totp = state.totp.filter(a => a.id !== account.id); renderTotp(); renderProfile(); return; }
        try { await deleteItem(state.uid, 'totp', account.id); toast('Removed'); }
        catch (err){ toast(friendlyError(err), 'err'); }
        break;
      }
    }
  });

  /* passwords */
  $('#add-cred-btn').onclick = () => openCredSheet();
  $('#save-cred').onclick = saveCredential;
  $('#accTypeSelect').onchange = (e) => setOpen($('#customPlatformDiv'), e.target.value === 'Other');
  $('#sheet-gen').onclick = () => {
    const pw = makePassword();
    if (pw){ $('#sitePass').value = pw; $('#sitePass').type = 'text'; toast('Password generated'); }
  };
  $('#searchInput').addEventListener('input', (e) => { state.search = e.target.value; renderVault(); });
  $('#type-filters').addEventListener('click', (e) => {
    const chip = e.target.closest('[data-filter]');
    if (!chip) return;
    state.filter = chip.dataset.filter;
    renderVault();
  });

  $('#vault-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const id = btn.closest('.vault-row').dataset.id;
    const item = state.vault.find(v => v.id === id);
    if (!item) return;

    switch (btn.dataset.act){
      case 'peek':
        state.revealed.has(id) ? state.revealed.delete(id) : state.revealed.add(id);
        renderVault();
        break;
      case 'copy-user': copyText(item.username || '', 'Username copied'); break;
      case 'copy-pass': copyText(item.password || '', 'Password copied'); break;
      case 'edit': openCredSheet(item); break;
      case 'delete': {
        const ok = await confirmAction('Delete this password?',
          `${item.platformName} · ${item.username} will be removed from every device.`, 'Delete');
        if (!ok) return;
        if (state.preview){ state.vault = state.vault.filter(v => v.id !== id); renderVault(); renderProfile(); return; }
        try { await deleteItem(state.uid, 'vault', id); toast('Password deleted'); }
        catch (err){ toast(friendlyError(err), 'err'); }
        break;
      }
    }
  });

  /* generator */
  const lengthInput = $('#passLength');
  const paintRange = () => {
    const pct = (lengthInput.value - lengthInput.min) / (lengthInput.max - lengthInput.min) * 100;
    lengthInput.style.setProperty('--pct', pct + '%');
    $('#lengthValue').textContent = lengthInput.value;
  };
  lengthInput.addEventListener('input', () => { paintRange(); showGenerated(makePassword()); });
  paintRange();
  $('#gen-make').onclick = () => showGenerated(makePassword());
  $('#gen-refresh').onclick = () => showGenerated(makePassword());
  $('#gen-copy').onclick = () => {
    const value = $('#generatedPassword').textContent;
    if (value && value !== 'Press generate') copyText(value, 'Password copied');
  };
  $$('.switch-grid input').forEach(cb => cb.addEventListener('change', () => showGenerated(makePassword())));

  /* profile */
  $('#avatar-edit').onclick = () => $('#photo-file-input').click();
  $('#change-photo').onclick = () => $('#photo-file-input').click();
  $('#photo-file-input').addEventListener('change', handlePhotoPicked);
  $('#crop-save').onclick = saveCroppedPhoto;
  $('#signout-btn').onclick = signOutNow;
  $('#reset-pass').onclick = async () => {
    if (state.preview) return toast('Preview mode has no account.', 'info');
    try { await resetPassword(state.profile.email || auth.currentUser.email); toast('Reset link sent'); }
    catch (err){ toast(friendlyError(err), 'err'); }
  };

  /* settings */
  $('#theme-seg').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-theme-val]');
    if (!btn) return;
    state.settings.theme = btn.dataset.themeVal;
    persistSettings();
  });
  $('#accent-swatches').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-accent-val]');
    if (!btn) return;
    state.settings.accent = btn.dataset.accentVal;
    persistSettings();
  });
  $('#autolock-select').onchange = (e) => { state.settings.autolock = Number(e.target.value); persistSettings(); };
  $('#privacy-toggle').onchange = (e) => {
    state.settings.privacy = e.target.checked;
    state.shown.clear();
    persistSettings();
    tickCodes(true);
  };
  $('#change-key-btn').onclick = () => {
    if (state.preview) return toast('Preview mode has no key.', 'info');
    showKeyScreen('rotate');
  };
  $('#export-btn').onclick = exportBackup;
  $('#import-btn').onclick = () => $('#importFileInput').click();
  $('#importFileInput').addEventListener('change', (e) => { if (e.target.files[0]) importBackup(e.target.files[0]); e.target.value=''; });
  $('#wipe-btn').onclick = async () => {
    if (state.preview) return toast('Nothing is stored in preview mode.', 'info');
    const ok = await confirmAction('Delete everything?',
      'All 2FA accounts and passwords will be removed from Firebase. This cannot be undone.', 'Delete all');
    if (!ok) return;
    try { await deleteAll(state.uid, 'vault'); await deleteAll(state.uid, 'totp'); toast('Vault cleared'); }
    catch (err){ toast(friendlyError(err), 'err'); }
  };

  /* FAB */
  $('#fab').onclick = () =>
    $('#tab-auth').classList.contains('active') ? openTotpSheet() : openCredSheet();

  /* sheets + keyboard */
  document.addEventListener('click', (e) => {
    const closer = e.target.closest('[data-close]');
    if (closer) closeSheet(closer.closest('.sheet-root').id);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllSheets();
    if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)
        && !$('#app-window').classList.contains('hidden')){
      e.preventDefault();
      ($('#tab-auth').classList.contains('active') ? $('#totpSearch') : $('#searchInput')).focus();
    }
  });

  ['pointerdown','keydown','wheel'].forEach(evt =>
    window.addEventListener(evt, resetIdleTimer, { passive:true }));
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tickCodes(true); });
  window.addEventListener('online',  () => setSync('idle'));
  window.addEventListener('offline', () => setSync('offline'));
}

/* ═══════════════ boot ═══════════════ */

async function boot(){
  wire();
  setAuthMode(false);
  applySettings();

  if (!isSecureEnough()){
    toast('Open the app over https:// or localhost — encryption needs a secure page.', 'err');
  }

  await finishRedirectLogin();
  setTimeout(() => $('#splash-screen').classList.add('gone'), 1500);

  observeAuthState(async (user) => {
    if (!user){
      if (!state.preview){ show('auth'); startDemoTicker(); }
      return;
    }

    stopDemoTicker();
    state.uid = user.uid;
    state.preview = false;

    try {
      let profile = await getProfile(user.uid);
      if (!profile){
        const parts = (user.displayName || '').split(' ');
        profile = {
          firstName: parts[0] || (user.email || '').split('@')[0],
          lastName: parts.slice(1).join(' '),
          email: user.email || '',
          photoUrl: user.photoURL || '',
          createdAt: Date.now()
        };
        await saveProfile(user.uid, profile);
      }
      if (!profile.email && user.email){
        profile.email = user.email;
        saveProfile(user.uid, { email: user.email }).catch(() => {});
      }
      state.profile = profile;
      state.settings = { ...state.settings, ...(profile.settings || {}) };
      applySettings();
      renderProfile();
      showKeyScreen(profile.kdf && profile.verifier ? 'unlock' : 'create');
    } catch (err){
      toast(friendlyError(err), 'err');
      show('auth');
    }
  });
}

window.addEventListener('DOMContentLoaded', boot);

if ('serviceWorker' in navigator){
  window.addEventListener('load', () => navigator.serviceWorker.register('./service-worker.js').catch(() => {}));
}
