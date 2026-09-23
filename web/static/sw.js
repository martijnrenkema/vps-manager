// Bump the version whenever the caching strategy changes; old caches are
// deleted on activate. Versioned /static/ URLs (?v=<app version>) change with
// every release, so stale-while-revalidate never serves an outdated release.
const CACHE_NAME = 'vps-manager-v5';
const STATIC_ASSETS = [
    '/static/logo.png',
    '/static/icon-192.png',
    '/static/icon-512.png',
];
// Keep the static cache from growing forever across releases.
const MAX_STATIC_ENTRIES = 80;

const OFFLINE_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>Offline - VPS Manager</title><style>' +
    'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;' +
    'background:#0b0e14;color:#e6edf3;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}' +
    'main{max-width:360px;padding:24px;text-align:center}h1{font-size:18px;margin:0 0 8px}' +
    'p{color:#8b949e;margin:0 0 20px}button{background:#2f6feb;color:#fff;border:0;border-radius:8px;' +
    'padding:9px 16px;font:inherit;cursor:pointer}</style></head><body><main>' +
    '<h1>You are offline</h1><p>VPS Manager can\'t reach the server right now. Check your connection and try again.</p>' +
    '<button onclick="location.reload()">Retry</button></main></body></html>';

// Install: pre-cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)).catch(() => {})
    );
    self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
        ).then(() => self.clients.claim())
    );
});

async function trimCache(cache) {
    const keys = await cache.keys();
    const excess = keys.length - MAX_STATIC_ENTRIES;
    for (let i = 0; i < excess; i++) await cache.delete(keys[i]);
}

// Static assets: stale-while-revalidate
async function staleWhileRevalidate(event) {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(event.request);
    const network = fetch(event.request).then(async (response) => {
        if (response && response.ok && response.type === 'basic') {
            await cache.put(event.request, response.clone());
            trimCache(cache);
        }
        return response;
    });
    if (cached) {
        event.waitUntil(network.catch(() => {}));
        return cached;
    }
    return network;
}

// Navigations: always network (pages hold live data + CSRF tokens and are
// never cached); show a small offline page when the network is unreachable.
async function networkFirstNavigation(event) {
    try {
        const preload = event.preloadResponse ? await event.preloadResponse : null;
        return preload || await fetch(event.request);
    } catch (e) {
        return new Response(OFFLINE_HTML, {
            status: 503,
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
        });
    }
}

self.addEventListener('fetch', (event) => {
    const req = event.request;
    // Let the browser handle everything we don't explicitly manage: non-GET,
    // cross-origin, API calls and streams (SSE) never go through the worker.
    if (req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;
    if (url.pathname.startsWith('/api/')) return;
    if ((req.headers.get('accept') || '').includes('text/event-stream')) return;

    if (url.pathname.startsWith('/static/')) {
        event.respondWith(staleWhileRevalidate(event));
        return;
    }
    if (req.mode === 'navigate') {
        event.respondWith(networkFirstNavigation(event));
    }
    // Anything else (JSON endpoints outside /api/, sw.js, manifest.json, ...):
    // no respondWith -> default network behaviour.
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
