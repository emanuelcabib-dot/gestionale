self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  // Richiesto da Chrome per validare la PWA
  e.respondWith(fetch(e.request).catch(() => new Response("Offline")));
});
