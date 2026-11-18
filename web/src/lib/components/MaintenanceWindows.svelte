<script lang="ts">
	import { BellOff } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';
	import { describeMute } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Mute } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import MuteDialog from './MuteDialog.svelte';

	/** Alert maintenance windows and snoozes for clients and sites (one agent's are on the agent). */
	$effect(() => {
		loadClients();
	});
	const mutes = resource(() => api.get<Mute[]>(`/alert-mutes${qs({ client_id: clientId() })}`));
	let adding = $state(false);
	async function remove(m: Mute) {
		if (await attempt(() => api.del(`/alert-mutes/${m.id}`), m.ends_at ? 'Snooze ended.' : 'Maintenance window removed.')) mutes.reload();
	}
</script>

<section class="card mt-6" aria-labelledby="mutes-title">
	<header class="border-border flex min-h-12 flex-wrap items-center gap-2 border-b px-4 py-2">
		<div class="min-w-0 flex-1">
			<h2 id="mutes-title" class="panel-title">Maintenance windows</h2>
			<p class="text-muted text-xs">Alerts that open during these are kept, but nobody is notified and no ticket opens. Snoozes for one agent are set on the agent.</p>
		</div>
		{#if can('technician') && clients.list.length}<Button size="sm" icon={BellOff} onclick={() => (adding = true)}>Add window</Button>{/if}
	</header>
	{#if mutes.data?.length}
		<ul class="divide-border divide-y">
			{#each mutes.data as m (m.id)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
					<div class="min-w-0 flex-1">
						<div class="flex flex-wrap items-center gap-2">
							{#if m.agent_id}<a class="hover:text-accent font-medium" href="/agents/{m.agent_id}?tab=alerts">{m.target_name}</a>{:else}<span class="font-medium">{m.target_name}</span>{/if}
							<span class="text-muted">{describeMute(m, datetime)}</span>
							{#if m.active}<Badge tone="warning">Now</Badge>{/if}
						</div>
						{#if m.reason || m.created_by_name}<div class="text-muted text-xs">{[m.reason, m.created_by_name].filter(Boolean).join(' · ')}</div>{/if}
					</div>
					{#if can('technician')}<Button size="sm" variant="ghost" onclick={() => remove(m)}>{m.ends_at ? 'End' : 'Remove'}</Button>{/if}
				</li>
			{/each}
		</ul>
	{:else if !mutes.loading}
		<EmptyState compact title="No maintenance windows" description="Add one for regular work (nightly backups, weekend patching) so planned reboots don't page anyone." />
	{/if}
</section>

{#if adding}<MuteDialog onclose={() => (adding = false)} onsaved={() => mutes.reload()} />{/if}
