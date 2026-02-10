// Service Worker to redirect index.pck requests to Backblaze B2
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // If requesting index.pck, redirect to Backblaze B2
    if (url.pathname.endsWith('/index.pck')) {
        event.respondWith(
            fetch('https://f004.backblazeb2.com/file/game-stuff/index.pck', {
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
