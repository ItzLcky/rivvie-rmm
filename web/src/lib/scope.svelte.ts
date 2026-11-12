/**
 * The client switcher: `?client=<id>` scopes every list page to one client. It lives in the
 * URL so links and bookmarks carry it; `withClient()` adds it to internal links.
 */
import { page } from '$app/state';
import { api } from './api';
import type { Client } from './types';

export const clients = $state<{ list: Client[]; loaded: boolean }>({ list: [], loaded: false });

let inflight: Promise<void> | null = null;
export function loadClients(force = false): Promise<void> {
	if (clients.loaded && !force) return Promise.resolve();
	inflight ??= api
		.get<Client[]>('/clients')
		.then((c) => {
			clients.list = c;
			clients.loaded = true;
		})
		.catch(() => {})
		.finally(() => (inflight = null));
	return inflight;
}

export function clientId(): string {
	return page.url.searchParams.get('client') ?? '';
}

export function currentClient(): Client | undefined {
	const id = clientId();
	return id ? clients.list.find((c) => c.id === id) : undefined;
}

/** `href` with the current client scope appended (if one is selected). */
export function withClient(href: string, id = clientId()): string {
	if (!id) return href;
	const u = new URL(href, 'http://x');
	u.searchParams.set('client', id);
	return u.pathname + u.search + u.hash;
}

/** Pages whose lists the switcher filters in place; elsewhere it goes to the dashboard. */
export const SCOPED_PAGES = ['/', '/agents', '/jobs', '/clients', '/scripts', '/alerts', '/policies', '/schedules', '/tickets', '/projects', '/billing', '/contracts'];
