import { api } from './api';
import { prefs, setPref } from './prefs.svelte';
import { resource, type Resource } from './resource.svelte';
import type { Page } from './types';
import { param, qs, setParams } from './url.svelte';

/** The most rows "select all matching" picks. */
export const ALL_CAP = 5000;

/** Runs `fn` on `ids` in slices of `size` (bulk endpoints cap how many they take), adding up the results. */
export async function inBatches(ids: string[], size: number, fn: (slice: string[]) => Promise<unknown>): Promise<void> {
	for (let i = 0; i < ids.length; i += size) await fn(ids.slice(i, i + size));
}

/**
 * A server-paged list: `path()` returns the endpoint with its filters (read from the URL, so
 * they're tracked); the cursor (`?after=`/`?before=`) and page size are added here.
 * Call during component init.
 */
export function paged<T>(path: () => string): Resource<Page<T>> & {
	readonly rows: T[];
	readonly pageSize: number;
	next(): void;
	prev(): void;
	first(): void;
	setPageSize(n: number): void;
	/** Every row matching the filters (not just this page), up to `cap`. */
	all(cap?: number): Promise<T[]>;
} {
	const res = resource<Page<T>>(() => {
		const base = path();
		const sep = base.includes('?') ? '&' : '?';
		const cursor = qs({ after: param('after'), before: param('before'), limit: prefs.pageSize ?? 50 }).slice(1);
		return api.get<Page<T>>(`${base}${sep}${cursor}`);
	});
	// Getters, not Object.assign: that would copy `rows` once instead of reading it live.
	return {
		get data() {
			return res.data;
		},
		get error() {
			return res.error;
		},
		get loading() {
			return res.loading;
		},
		get busy() {
			return res.busy;
		},
		reload: res.reload,
		set: res.set,
		update: res.update,
		get rows() {
			return res.data?.items ?? [];
		},
		all: async (cap = ALL_CAP) => {
			const base = path();
			const sep = base.includes('?') ? '&' : '?';
			const out: T[] = [];
			let after: string | null = null;
			do {
				const p: Page<T> = await api.get<Page<T>>(`${base}${sep}${qs({ after, limit: 500 }).slice(1)}`);
				out.push(...p.items);
				after = p.next;
			} while (after && out.length < cap);
			return out.slice(0, cap);
		},
		get pageSize() {
			return prefs.pageSize ?? 50;
		},
		next: () => {
			if (res.data?.next) setParams({ after: res.data.next, before: null }, { push: true });
		},
		prev: () => {
			if (res.data?.prev) setParams({ before: res.data.prev, after: null }, { push: true });
		},
		first: () => {
			setParams({ after: null, before: null }, { push: true });
		},
		setPageSize: (n: number) => {
			setPref('pageSize', n);
			setParams({ after: null, before: null });
		}
	};
}
