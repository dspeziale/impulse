const CACHE_NAME = 'impulse-v1';
const ASSETS_TO_CACHE = [
    '/', // Cache the root
    '/static/img/impulse_logo.png',
    'https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/css/adminlte.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    'https://code.jquery.com/jquery-3.7.0.min.js',
    'https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js',
    'https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/js/adminlte.min.js'
];

// Install Event - Cache Core Assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            console.log('[SW] Caching shell assets');
            return cache.addAll(ASSETS_TO_CACHE);
        })
    );
    self.skipWaiting();
});

// Activate Event - Cleanup Old Caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keyList) => {
            return Promise.all(keyList.map((key) => {
                if (key !== CACHE_NAME) {
                    console.log('[SW] Removing old cache', key);
                    return caches.delete(key);
                }
            }));
        })
    );
    self.clients.claim();
});

// Fetch Event - Network First, then Cache
self.addEventListener('fetch', (event) => {
    // Skip non-GET requests (POST, etc. should always go to network)
    if (event.request.method !== 'GET') {
        return;
    }

    event.respondWith(
        fetch(event.request)
            .then((response) => {
                // If network fetch is successful, clone and cache it
                if (!response || response.status !== 200 || response.type !== 'basic') {
                    return response;
                }

                const responseToCache = response.clone();
                caches.open(CACHE_NAME)
                    .then((cache) => {
                        cache.put(event.request, responseToCache);
                    });

                return response;
            })
            .catch(() => {
                // If network fails, look in cache
                return caches.match(event.request);
            })
    );
});
