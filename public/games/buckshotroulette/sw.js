// Service Worker to redirect index.pck requests to Render B2 proxy
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // If requesting index.pck, redirect to Render proxy
    if (url.pathname.endsWith('/index.pck')) {
        event.respondWith(
            fetch('https://game-vault-pbhf.onrender.com/api/b2-proxy/index.pck', {
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
