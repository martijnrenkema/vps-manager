const CACHE_NAME = 'vps-manager-v1';
const STATIC_ASSETS = [
    '/static/style.css',
    '/static/logo.png',
    '/static/icon-192.png',
    '/static/icon-512.png',
    '/static/manifest.json',
];

// Install: pre-cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
    );
    self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

// Fetch: network-first for pages/API, cache-first for static assets
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Static assets: cache-first
    if (url.pathname.startsWith('/static/')) {
        event.respondWith(
            caches.match(event.request).then((cached) => cached || fetch(event.request))
        );
        return;
    }

    // Everything else: network-first (server data must be live)
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});

// Push notification received
self.addEventListener('push', (event) => {
    let data = { title: 'VPS Manager', body: 'Notification', tag: 'general' };
    if (event.data) {
        try {
            data = event.data.json();
        } catch (e) {
            data.body = event.data.text();
        }
    }

    const options = {
        body: data.body,
        icon: '/static/icon-192.png',
        badge: '/static/icon-192.png',
        tag: data.tag || 'general',
        data: { url: data.url || '/' },
        vibrate: [200, 100, 200],
    };

    event.waitUntil(self.registration.showNotification(data.title, options));
});

// Notification click: open/focus the app
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const url = event.notification.data?.url || '/';

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
            for (const client of windowClients) {
                if (client.url.includes(self.location.origin) && 'focus' in client) {
                    client.navigate(url);
                    return client.focus();
                }
            }
            return clients.openWindow(url);
        })
    );
});
