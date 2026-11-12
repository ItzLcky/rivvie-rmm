import { portal } from './api';
import type { PortalMe } from './types';

/** The signed-in portal contact, loaded once by the portal layout. */
export const me = $state<{ data: PortalMe | null; loading: boolean; error: string }>({ data: null, loading: false, error: '' });

let pending: Promise<void> | null = null;

export function loadMe(force = false): Promise<void> {
	if (pending && !force) return pending;
	if (me.data && !force) return Promise.resolve();
	me.loading = true;
	me.error = '';
	pending = portal
		.get<PortalMe>('/me')
		.then((d) => {
			me.data = d;
		})
		.catch((e) => {
			me.data = null;
			me.error = e instanceof Error ? e.message : String(e);
		})
		.finally(() => {
			me.loading = false;
			pending = null;
		});
	return pending;
}

/** Forget the contact (after signing out, or before signing in as someone else). */
export function clearMe() {
	me.data = null;
	me.error = '';
}
