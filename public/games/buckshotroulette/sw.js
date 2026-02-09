// Service Worker to redirect index.pck requests to GitHub
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // If requesting index.pck, redirect to GitHub
    if (url.pathname.endsWith('/index.pck')) {
        event.respondWith(
            fetch('https://github.com/nakkaaneesh1194-collab/Buckshot-Roulette-online-game-vault/releases/download/v1.0/index.pck', {
                mode: 'cors',
                credentials: 'omit'
            })
        );
    } else {
        // All other requests pass through normally
        event.respondWith(fetch(event.request));
    }
});

self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(clients.claim());
});
