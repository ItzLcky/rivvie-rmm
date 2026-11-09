/** Open alert counts for the sidebar badge, kept fresh by live alert events. */
import { api } from '#lib/api.js';
import { liveReload } from '#lib/live.svelte.js';
import type { Severity } from '#lib/types.js';

export const alertCounts = $state<Record<Severity, number> & { loaded: boolean }>({ critical: 0, warning: 0, info: 0, loaded: false });

async function load() {
	try {
		const c = await api.get<Partial<Record<Severity, number>>>('/alerts/summary');
		alertCounts.critical = c.critical ?? 0;
		alertCounts.warning = c.warning ?? 0;
		alertCounts.info = c.info ?? 0;
		alertCounts.loaded = true;
	} catch {
		/* the badge just stays as it was */
	}
}

/** Call once during the root layout's init; `active` says whether someone is signed in. */
export function trackAlerts(active: () => boolean) {
	$effect(() => {
		if (active()) load();
	});
	liveReload(() => active() && load(), (e) => e.type === 'alert', { debounceMs: 1500, pollMs: 60000 });
}

export function acknowledge(ids: string[]) {
	return api.post<{ changed: number }>('/alerts/bulk', { ids, action: 'acknowledge' });
}
export function resolve(ids: string[]) {
	return api.post<{ changed: number }>('/alerts/bulk', { ids, action: 'resolve' });
}
