<script lang="ts">
	import { LogOut, Monitor } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Session } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';

	/** `/auth/sessions` for your own, `/users/{id}/sessions` for an admin view. */
	let { base, revokeAllLabel = 'Sign out other sessions' }: { base: string; revokeAllLabel?: string } = $props();

	const res = resource(() => api.get<Session[]>(base));

	function describe(ua: string | null): string {
		if (!ua) return 'Unknown client';
		const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : null;
		const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : null;
		return browser && os ? `${browser} on ${os}` : ua.slice(0, 60);
	}
	const revoke = async (s: Session) => (await attempt(() => api.del(`${base}/${s.id}`), 'Session signed out.')) && res.reload();
	const revokeAll = async () => (await attempt(() => api.del(base), 'Other sessions signed out.')) && res.reload();
</script>

<Async {res} compact>
	{#snippet children(sessions)}
		<ul class="space-y-2">
			{#each sessions as s (s.id)}
				<li class="border-border flex items-center gap-3 rounded-md border px-3 py-2">
					<Monitor class="text-muted size-4 shrink-0" />
					<div class="min-w-0 flex-1">
						<div class="flex items-center gap-2 truncate text-sm" title={s.user_agent ?? ''}>
							{describe(s.user_agent)}
							{#if s.current}<Badge tone="accent">This session</Badge>{/if}
						</div>
						<div class="text-muted text-xs">Signed in {datetime(s.created_at)} · active {ago(s.last_seen_at)}</div>
					</div>
					{#if !s.current}<Button size="sm" variant="danger-ghost" onclick={() => revoke(s)}>Sign out</Button>{/if}
				</li>
			{:else}
				<li class="text-muted text-sm">No active sessions.</li>
			{/each}
		</ul>
		{#if sessions.some((s) => !s.current)}
			<div class="mt-3 flex justify-end"><Button size="sm" icon={LogOut} onclick={revokeAll}>{revokeAllLabel}</Button></div>
		{/if}
	{/snippet}
</Async>
