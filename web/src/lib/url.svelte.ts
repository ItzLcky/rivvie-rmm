/**
 * URL-backed page state: filters, sort, cursor, tab. Everything a view shows is in the query
 * string, so it can be bookmarked, shared and restored with Back.
 */
import { goto } from '$app/navigation';
import { page } from '$app/state';

export function param(name: string, fallback = ''): string {
	return page.url.searchParams.get(name) ?? fallback;
}

/** Params that address a page of results; changing any filter drops them. */
const PAGING = ['after', 'before'];

/**
 * Sets (or with null/'' removes) query params on the current URL, replacing the history
 * entry. Changing anything other than the page cursor itself resets to the first page.
 */
export function setParams(patch: Record<string, string | number | null | undefined>, opts: { push?: boolean } = {}) {
	const u = new URL(page.url.href);
	const paging = Object.keys(patch).some((k) => PAGING.includes(k));
	if (!paging) for (const k of PAGING) u.searchParams.delete(k);
	for (const [k, v] of Object.entries(patch)) {
		if (v === null || v === undefined || v === '') u.searchParams.delete(k);
		else u.searchParams.set(k, String(v));
	}
	if (u.search === page.url.search) return;
	return goto(u, { replace: !opts.push, reset: false });
}

/** Sort state from `?sort=&dir=`, with a click handler that cycles asc → desc → default. */
export function sortState(defaultKey: string, defaultDir: 'asc' | 'desc' = 'asc') {
	return {
		get key() {
			return param('sort', defaultKey);
		},
		get dir(): 'asc' | 'desc' {
			const d = param('dir');
			return d === 'asc' || d === 'desc' ? d : param('sort') ? 'asc' : defaultDir;
		},
		toggle(key: string) {
			if (this.key !== key) setParams({ sort: key, dir: 'asc' });
			else if (this.dir === 'asc') setParams({ sort: key, dir: 'desc' });
			else setParams({ sort: null, dir: null });
		}
	};
}

/** Builds `?…` from params, skipping empty values. */
export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
	const u = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v));
	const s = u.toString();
	return s ? `?${s}` : '';
}
