/**
 * One Server-Sent Events stream (`/api/events`) for the whole dashboard. Pages subscribe to
 * the events they show instead of polling; while the stream is down they fall back to
 * polling (see `liveReload`).
 */
import type { Metrics } from './types';

export type LiveEvent =
	| { type: 'hello' }
	| { type: 'resync' }
	| { type: 'agent'; id: string; online: boolean; last_metrics?: Metrics }
	| { type: 'job'; id: string; agent_id: string; status: string; output: boolean }
	| { type: 'jobs' }
	| { type: 'alert'; id: string; agent_id: string; state: 'open' | 'acknowledged' | 'resolved' }
	| { type: 'services'; agent_id: string };

export const live = $state<{ status: 'connecting' | 'live' | 'offline' }>({ status: 'connecting' });

type Listener = (e: LiveEvent) => void;
const listeners = new Set<Listener>();
let source: EventSource | null = null;
let retry: ReturnType<typeof setTimeout> | undefined;
let backoff = 1000;
let everConnected = false;

function emit(e: LiveEvent) {
	for (const l of listeners) {
		try {
			l(e);
		} catch (err) {
			console.error('live listener', err);
		}
	}
}

export function connectLive() {
	if (source || typeof EventSource === 'undefined') return;
	clearTimeout(retry);
	live.status = 'connecting';
	source = new EventSource('/api/events');
	source.onmessage = (m) => {
		let e: LiveEvent;
		try {
			e = JSON.parse(m.data);
		} catch {
			return;
		}
		if (e.type === 'hello') {
			live.status = 'live';
			backoff = 1000;
			// Anything may have changed while we were disconnected.
			if (everConnected) emit({ type: 'resync' });
			everConnected = true;
			return;
		}
		emit(e);
	};
	source.onerror = () => {
		// The browser retries by itself on network errors, but not after an HTTP error (e.g.
		// 401 when the session ended). Close and retry with backoff either way.
		source?.close();
		source = null;
		live.status = 'offline';
		retry = setTimeout(connectLive, backoff);
		backoff = Math.min(backoff * 2, 30000);
	};
}

export function disconnectLive() {
	clearTimeout(retry);
	source?.close();
	source = null;
	everConnected = false;
	live.status = 'connecting';
}

/** Subscribes for the lifetime of the calling component (call during init). */
export function onLive(fn: Listener) {
	$effect(() => {
		listeners.add(fn);
		return () => listeners.delete(fn);
	});
}

/**
 * Reloads `reload` (debounced) whenever `matches` accepts an event, after a resync, and on an
 * interval while the live stream is down. Call during component init.
 */
export function liveReload(reload: () => void, matches: (e: LiveEvent) => boolean, opts: { debounceMs?: number; pollMs?: number } = {}) {
	const { debounceMs = 800, pollMs = 15000 } = opts;
	let t: ReturnType<typeof setTimeout> | undefined;
	const soon = () => {
		clearTimeout(t);
		t = setTimeout(reload, debounceMs);
	};
	onLive((e) => {
		if (e.type === 'resync' || matches(e)) soon();
	});
	$effect(() => {
		if (live.status === 'live') return;
		const i = setInterval(reload, pollMs);
		return () => clearInterval(i);
	});
	$effect(() => () => clearTimeout(t));
}
