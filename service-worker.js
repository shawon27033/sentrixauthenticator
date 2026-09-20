/* Sentrix Vault — service worker
   App shell is cached so the app opens offline, but the code is fetched
   network-first so a new deploy is picked up on the next load.
   Firebase traffic is never cached: stale vault data would be worse than none. */

const CACHE = 'sentrix-vault-v4';
const SHELL = [
  './',
  './index.html',
  './manifest.json',
  './css/style.css',
  './js/app.js',
  './js/firebase.js',
  './js/crypto.js',
  './js/totp.js',
  './images/favicon.svg',
  './images/avatar.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

const SKIP_HOSTS = [
  'firestore.googleapis.com',
  'identitytoolkit.googleapis.com',
  'securetoken.googleapis.com',
  'firebasestorage.googleapis.com',
  'www.googleapis.com'
];

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (SKIP_HOSTS.some(h => url.hostname.endsWith(h))) return;

  const sameOrigin = url.origin === self.location.origin;

  if (sameOrigin){
    // network first, fall back to the cached shell when offline
    event.respondWith(
      fetch(request)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(request, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(request).then(hit => hit || caches.match('./index.html')))
    );
    return;
  }

  // CDN fonts/icons: cache first, they are versioned
  event.respondWith(
    caches.match(request).then(hit => hit || fetch(request).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(request, copy)).catch(() => {});
      return res;
    }).catch(() => hit))
  );
});
