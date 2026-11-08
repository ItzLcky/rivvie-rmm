<script lang="ts">
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import type { Session } from '#lib/types.js';

	/** `/auth/sessions` for your own, `/users/{id}/sessions` for an admin view. */
	let { base, revokeAllLabel = 'Sign out other sessions' }: { base: string; revokeAllLabel?: string } = $props();

	let sessions = $state<Session[]>([]);
	let error = $state('');

	const load = () =>
		api.get<Session[]>(base).then((s) => (sessions = s)).catch((e) => (error = (e as Error).message));
	$effect(() => {
		load();
	});

	function describe(ua: string | null): string {
		if (!ua) return 'Unknown client';
		const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : null;
		const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : null;
		return browser && os ? `${browser} on ${os}` : ua.slice(0, 60);
	}

	async function revoke(s: Session) {
		error = '';
		try {
			await api.del(`${base}/${s.id}`);
			await load();
		} catch (e) {
			error = (e as Error).message;
		}
	}
	async function revokeAll() {
		error = '';
		try {
			await api.del(base);
			await load();
		} catch (e) {
			error = (e as Error).message;
		}
	}
	const others = $derived(sessions.filter((s) => !s.current).length);
</script>

<div class="space-y-2">
	{#each sessions as s (s.id)}
		<div class="flex items-center justify-between gap-3 rounded-md border border-slate-800 px-3 py-2">
			<div class="min-w-0">
				<div class="truncate text-sm" title={s.user_agent ?? ''}>
					{describe(s.user_agent)}
					{#if s.current}<span class="ml-1 rounded bg-sky-900/60 px-1.5 py-0.5 text-xs text-sky-300">this session</span>{/if}
				</div>
				<div class="text-xs text-slate-500">Signed in {datetime(s.created_at)} · active {ago(s.last_seen_at)}</div>
			</div>
			{#if !s.current}<button class="btn-danger shrink-0 py-1 text-xs" onclick={() => revoke(s)}>Revoke</button>{/if}
		</div>
	{:else}
		<p class="text-sm text-slate-500">No active sessions.</p>
	{/each}
	{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
	{#if others > 0}
		<div class="flex justify-end"><button class="btn-ghost text-xs" onclick={revokeAll}>{revokeAllLabel}</button></div>
	{/if}
</div>
