/* MAYBE switch to GoogleChrome/workbox later */
var cacheName = 'yew-pwa';
var filesToCache = [
  './',
  './index.html',
  './app.js',
  './app_bg.wasm',
  './worker.js',
  './worker_bg.wasm',
  './icon-32.png',
  './icon-16.png',
  './bulma.1.0.4.min.css'
];


/* Start the service worker and cache all of the app's content */
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(cacheName).then(function(cache) {
      return cache.addAll(filesToCache);
    })
  );
});

/* Serve cached content when offline */
self.addEventListener('fetch', function(e) {
  e.respondWith(
    caches.match(e.request).then(function(response) {
      return response || fetch(e.request);
    })
  );
});
