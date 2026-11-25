/// <reference types="@sveltejs/kit" />
/**
 * The installed app's service worker (docs/design/pwa.md): the app shell from a cache, so it
 * starts without the network; an offline page for navigations that fail; and Web Push.
 *
 * API responses are never cached: they hold client data. Requests to /api go straight to the
 * network, untouched.
 */
import { version } from '$app/env';
import { assets, immutable } from '$app/manifest';

const sw = self as unknown as ServiceWorkerGlobalScope;
const CACHE = `rmm-shell-${version}`;
const OFFLINE = '/offline.html';
const ASSETS = [...immutable, ...assets].map((a) => `/${a.path.replace(/^\//, '')}`);

sw.addEventListener('install', (event) => {
	event.waitUntil(
		caches
			.open(CACHE)
			.then((c) => c.addAll(ASSETS.includes(OFFLINE) ? ASSETS : [...ASSETS, OFFLINE]))
			.then(() => sw.skipWaiting())
	);
});

sw.addEventListener('activate', (event) => {
	event.waitUntil(
		caches
			.keys()
			.then((keys) => Promise.all(keys.filter((k) => k.startsWith('rmm-shell-') && k !== CACHE).map((k) => caches.delete(k))))
			.then(() => sw.clients.claim())
	);
});

sw.addEventListener('fetch', (event) => {
	const req = event.request;
	if (req.method !== 'GET') return;
	const url = new URL(req.url);
	if (url.origin !== sw.location.origin || url.pathname.startsWith('/api/') || url.pathname === '/manifest.webmanifest') return;
	if (ASSETS.includes(url.pathname)) {
		event.respondWith(caches.match(req).then((hit) => hit ?? fetch(req)));
		return;
	}
	if (req.mode === 'navigate') {
		event.respondWith(fetch(req).catch(async () => (await caches.match(OFFLINE)) ?? Response.error()));
	}
});

interface PushPayload {
	title?: string;
	body?: string;
	url?: string;
	alert_id?: string | null;
	tag?: string;
	kind?: string;
}

sw.addEventListener('push', (event) => {
	let data: PushPayload = {};
	try {
		data = event.data?.json() ?? {};
	} catch {
		data = { title: event.data?.text() };
	}
	const actions = data.alert_id ? [{ action: 'ack', title: 'Acknowledge' }] : [];
	event.waitUntil(
		sw.registration.showNotification(data.title || 'RMM', {
			body: data.body,
			tag: data.tag,
			icon: '/icons/icon-192.png',
			badge: '/icons/icon-192.png',
			data: { url: data.url || '/alerts', alert_id: data.alert_id },
			requireInteraction: data.kind === 'page',
			// Not in every lib.dom version yet.
			...({ actions } as object)
		})
	);
});

async function open(url: string) {
	const all = await sw.clients.matchAll({ type: 'window', includeUncontrolled: true });
	const same = all.find((c) => new URL(c.url).origin === sw.location.origin) as WindowClient | undefined;
	if (same) {
		await same.focus();
		return same.navigate(url);
	}
	return sw.clients.openWindow(url);
}

sw.addEventListener('notificationclick', (event) => {
	const n = event.notification;
	const { url, alert_id } = (n.data ?? {}) as { url: string; alert_id?: string };
	n.close();
	if (event.action === 'ack' && alert_id) {
		// The session cookie goes with it; signed out (or no right to), open the alert instead.
		event.waitUntil(
			fetch(`/api/alerts/${alert_id}/acknowledge`, { method: 'POST', credentials: 'same-origin' }).then((r) => (r.ok ? undefined : open(url)), () => open(url))
		);
		return;
	}
	event.waitUntil(open(url));
});
