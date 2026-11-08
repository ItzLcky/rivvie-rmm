import { api } from './api';
import { prefs, setPref } from './prefs.svelte';
import { resource, type Resource } from './resource.svelte';
import type { Page } from './types';
import { param, qs, setParams } from './url.svelte';

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
