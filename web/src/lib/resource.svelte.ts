import { untrack } from 'svelte';

/**
 * A fetched value with its loading and error state, refetched whenever reactive values read
 * by `fetcher` (before its first `await`) change. Background reloads keep showing the old
 * data, and late responses from superseded requests are dropped.
 *
 * Render it with `<Async res={...}>` to get the skeleton / error-with-retry / empty states.
 * Call during component init.
 */
export interface Resource<T> {
	readonly data: T | undefined;
	readonly error: Error | null;
	/** True only while there's nothing to show yet (first load, or after the inputs changed). */
	readonly loading: boolean;
	/** True during any request, including background reloads. */
	readonly busy: boolean;
	reload(): Promise<void>;
	/** Replace the data locally, e.g. for an optimistic update. */
	set(data: T): void;
	update(fn: (d: T) => T): void;
}

/**
 * `keep` (default true): when the inputs change, keep showing the old data (marked `busy`)
 * until the new data arrives, as tables do while paging. Detail pages pass false, so they
 * show a skeleton instead of the previous item.
 */
export function resource<T>(fetcher: () => Promise<T>, opts: { keep?: boolean } = {}): Resource<T> {
	const keep = opts.keep ?? true;
	const s = $state({ data: undefined as T | undefined, error: null as Error | null, loading: true, busy: true });
	let gen = 0;

	function run(background: boolean): Promise<void> {
		const mine = ++gen;
		untrack(() => {
			s.busy = true;
			if (!background && (!keep || s.data === undefined)) {
				s.loading = true;
				if (!keep) s.data = undefined;
			}
		});
		let p: Promise<T>;
		try {
			p = fetcher();
		} catch (e) {
			p = Promise.reject(e);
		}
		return p.then(
			(d) => {
				if (mine !== gen) return;
				s.data = d;
				s.error = null;
				s.loading = false;
				s.busy = false;
			},
			(e) => {
				if (mine !== gen) return;
				s.error = e instanceof Error ? e : new Error(String(e));
				s.loading = false;
				s.busy = false;
			}
		);
	}

	$effect(() => {
		run(false);
	});

	return {
		get data() {
			return s.data;
		},
		get error() {
			return s.error;
		},
		get loading() {
			return s.loading;
		},
		get busy() {
			return s.busy;
		},
		reload: () => run(true),
		set: (d) => {
			s.data = d;
		},
		update: (fn) => {
			if (s.data !== undefined) s.data = fn(s.data);
		}
	};
}
