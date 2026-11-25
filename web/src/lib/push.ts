/** Web Push on this device: subscribe through the service worker and tell the server. */
import { api } from '#lib/api.js';

export function pushSupported(): boolean {
	return typeof window !== 'undefined' && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

/** Installed to the home screen (or the desktop) and running as an app. */
export function standalone(): boolean {
	if (typeof window === 'undefined') return false;
	return window.matchMedia('(display-mode: standalone)').matches || (navigator as Navigator & { standalone?: boolean }).standalone === true;
}

/** iPhone and iPad: push needs the app added to the home screen, on iOS 16.4 or later. */
export function ios(): boolean {
	return typeof navigator !== 'undefined' && (/iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1));
}

function bytes(b64url: string): Uint8Array<ArrayBuffer> {
	const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64url.length % 4)) % 4);
	const raw = atob(b64);
	const out = new Uint8Array(new ArrayBuffer(raw.length));
	for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
	return out;
}

export async function currentSubscription(): Promise<PushSubscription | null> {
	if (!pushSupported()) return null;
	const reg = await navigator.serviceWorker.getRegistration();
	return (await reg?.pushManager.getSubscription()) ?? null;
}

export async function enablePush(): Promise<void> {
	if (!pushSupported()) throw new Error('This browser can’t receive notifications.');
	const permission = await Notification.requestPermission();
	if (permission !== 'granted') throw new Error('Notifications are blocked for this site: allow them in the browser’s site settings.');
	const reg = await navigator.serviceWorker.ready;
	const { public_key } = await api.get<{ public_key: string }>('/push/key');
	const sub = (await reg.pushManager.getSubscription()) ?? (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: bytes(public_key) }));
	await api.post('/push/subscriptions', sub.toJSON());
}

export async function disablePush(): Promise<void> {
	const sub = await currentSubscription();
	if (!sub) return;
	await api.del('/push/subscriptions', { endpoint: sub.endpoint });
	await sub.unsubscribe();
}
