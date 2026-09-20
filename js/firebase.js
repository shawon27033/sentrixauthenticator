/* ------------------------------------------------------------------
   firebase.js — the only place that talks to Firebase.
   Nothing is written to localStorage: the vault, the 2FA accounts and
   the settings all live in Firestore, so signing in on another device
   brings everything with it.
------------------------------------------------------------------ */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth, setPersistence, browserLocalPersistence, browserSessionPersistence,
  createUserWithEmailAndPassword, signInWithEmailAndPassword,
  GoogleAuthProvider, signInWithPopup, signInWithRedirect, getRedirectResult,
  sendPasswordResetEmail, signOut, onAuthStateChanged, updateProfile
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore, doc, collection, setDoc, getDoc, addDoc, updateDoc,
  deleteDoc, onSnapshot, query, orderBy, getDocs, writeBatch, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import {
  getStorage, ref, uploadString, getDownloadURL
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyDBSRyoljX4HOGnO0zLAiWOBhoJ9x4UMvY",
  authDomain: "sentrix-by-pn.firebaseapp.com",
  projectId: "sentrix-by-pn",
  storageBucket: "sentrix-by-pn.firebasestorage.app",
  messagingSenderId: "1031537926254",
  appId: "1:1031537926254:web:d534122c685eef2a05067f",
  measurementId: "G-1R1Z48VCEQ"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);

// Keeps the session alive after a reload or an app restart.
setPersistence(auth, browserLocalPersistence).catch(() => {});

/** "Keep me signed in" — local survives a restart, session ends with the tab. */
export const setRemember = (remember) =>
  setPersistence(auth, remember ? browserLocalPersistence : browserSessionPersistence).catch(() => {});

/* ───────── Auth ───────── */

export const registerUser = (email, password) => createUserWithEmailAndPassword(auth, email, password);
export const loginUser    = (email, password) => signInWithEmailAndPassword(auth, email, password);
export const logoutUser   = () => signOut(auth);
export const resetPassword = (email) => sendPasswordResetEmail(auth, email);
export const observeAuthState = (cb) => onAuthStateChanged(auth, cb);
export const setDisplayName = (name) => updateProfile(auth.currentUser, { displayName: name });

export async function loginWithGoogle(){
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  try {
    return await signInWithPopup(auth, provider);
  } catch (err) {
    // Popups are blocked inside installed PWAs and some in-app browsers.
    if (['auth/popup-blocked','auth/operation-not-supported-in-this-environment','auth/cancelled-popup-request']
        .includes(err.code)) {
      await signInWithRedirect(auth, provider);
      return null;
    }
    throw err;
  }
}
export const finishRedirectLogin = () => getRedirectResult(auth).catch(() => null);

/* ───────── Profile document ───────── */

const userDoc = (uid) => doc(db, 'users', uid);

export async function getProfile(uid){
  const snap = await getDoc(userDoc(uid));
  return snap.exists() ? snap.data() : null;
}

export async function saveProfile(uid, data){
  return setDoc(userDoc(uid), { ...data, updatedAt: serverTimestamp() }, { merge: true });
}

export async function saveSettings(uid, settings){
  return setDoc(userDoc(uid), { settings }, { merge: true });
}

/** Store the KDF parameters + verifier so any device can unlock with the master key. */
export async function saveKeyMaterial(uid, kdf, verifier){
  return setDoc(userDoc(uid), { kdf, verifier }, { merge: true });
}

export async function uploadAvatar(uid, dataUrl){
  const fileRef = ref(storage, `avatars/${uid}.jpg`);
  await uploadString(fileRef, dataUrl, 'data_url');
  return getDownloadURL(fileRef);
}

/* ───────── Vault + authenticator collections ─────────
   Both hold only ciphertext:
     { blob: { iv, ct }, accType, createdAt, updatedAt }
   accType stays readable so the list can be filtered without decrypting.
---------------------------------------------------------- */

const vaultCol = (uid) => collection(db, 'users', uid, 'vault');
const totpCol  = (uid) => collection(db, 'users', uid, 'authenticators');
const colFor   = (uid, kind) => (kind === 'totp' ? totpCol(uid) : vaultCol(uid));

/** Live listener — fires again on every device the moment something changes. */
export function watchCollection(uid, kind, onData, onError){
  const q = query(colFor(uid, kind), orderBy('createdAt', 'desc'));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map(d => ({ id: d.id, ...d.data() }))),
    (err) => onError && onError(err)
  );
}

export async function addItem(uid, kind, payload){
  const docRef = await addDoc(colFor(uid, kind), {
    ...payload,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  });
  return docRef.id;
}

export async function updateItem(uid, kind, id, payload){
  return updateDoc(doc(colFor(uid, kind), id), { ...payload, updatedAt: serverTimestamp() });
}

export async function deleteItem(uid, kind, id){
  return deleteDoc(doc(colFor(uid, kind), id));
}

/** Write many items at once — used by import and by re-keying. */
export async function bulkWrite(uid, kind, rows){
  const col = colFor(uid, kind);
  for (let i = 0; i < rows.length; i += 400){
    const batch = writeBatch(db);
    for (const row of rows.slice(i, i + 400)){
      if (row.id) batch.set(doc(col, row.id), row.data, { merge: true });
      else        batch.set(doc(col),        { ...row.data, createdAt: serverTimestamp(), updatedAt: serverTimestamp() });
    }
    await batch.commit();
  }
}

export async function readAll(uid, kind){
  const snap = await getDocs(colFor(uid, kind));
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

export async function deleteAll(uid, kind){
  const snap = await getDocs(colFor(uid, kind));
  for (let i = 0; i < snap.docs.length; i += 400){
    const batch = writeBatch(db);
    snap.docs.slice(i, i + 400).forEach(d => batch.delete(d.ref));
    await batch.commit();
  }
}
