<script lang="ts">
	import { BellOff, Check, CheckCheck, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { acknowledge, resolve } from '#lib/monitoring/alerts.svelte.js';
	import { kindLabels } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Alert, Mute, Page } from '#lib/types.js';
	import { describeMute } from '#lib/monitoring/labels.js';
	import Badge from '#lib/ui/Badge.svelte';
	import MuteDialog from '#lib/components/MuteDialog.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import AlertStateBadge from '#lib/components/AlertStateBadge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';

	let { agentId, hostname, onchange }: { agentId: string; hostname: string; onchange?: () => void } = $props();
	const mutes = resource(() => api.get<Mute[]>(`/alert-mutes?agent_id=${agentId}`));
	let snoozing = $state(false);

	async function endMute(m: Mute) {
		if (await attempt(() => api.del(`/alert-mutes/${m.id}`), m.ends_at ? 'Snooze ended.' : 'Maintenance window removed.')) {
			mutes.reload();
			res.reload();
			onchange?.();
		}
	}
	let view = $state<'active' | 'all'>('active');
	const res = resource(() => api.get<Page<Alert>>(`/alerts?agent_id=${agentId}&state=${view}&limit=200`));
	liveReload(() => res.reload(), (e) => e.type === 'alert' && e.agent_id === agentId, { debounceMs: 500 });
	let selected = $state(new Set<string>());

	async function apply(action: 'acknowledge' | 'resolve') {
		const ids = [...selected];
		if (await attempt(() => (action === 'acknowledge' ? acknowledge(ids) : resolve(ids)), action === 'acknowledge' ? 'Acknowledged.' : 'Resolved.')) {
			selected = new Set();
			res.reload();
		}
	}
</script>

{#snippet sevCell(a: Alert)}<SeverityBadge severity={a.severity} />{/snippet}
{#snippet titleCell(a: Alert)}
	<a class="hover:text-accent font-medium" href="/alerts/{a.id}">{a.title}</a>
	<div class="text-muted truncate text-xs">{a.policy_name ?? kindLabels[a.kind]}{a.occurrences > 1 ? ` · ${num(a.occurrences)} times` : ''}</div>
{/snippet}
{#snippet stateCell(a: Alert)}<AlertStateBadge alert={a} />{/snippet}
{#snippet openedCell(a: Alert)}<span class="whitespace-nowrap" title={datetime(a.opened_at)}>{ago(a.opened_at)}</span>{/snippet}

<DataTable
	id="agent-alerts"
	caption="Alerts on this agent"
	rows={res.data?.items ?? []}
	key={(a) => a.id}
	loading={res.loading}
	busy={res.busy}
	scroll={false}
	bind:selected={() => (can('technician') ? selected : undefined), (v) => (selected = v ?? new Set())}
	rowHref={(a) => `/alerts/${a.id}`}
	columns={[
		{ id: 'severity', label: 'Severity', cell: sevCell, class: 'w-28' },
		{ id: 'title', label: 'Alert', cell: titleCell, hideable: false },
		{ id: 'state', label: 'State', cell: stateCell, from: 'sm' },
		{ id: 'opened', label: 'Opened', cell: openedCell }
	] satisfies Column<Alert>[]}
>
	{#snippet toolbar()}
		<Segmented label="Show" value={view} onchange={(v) => (view = v)} options={[{ value: 'active', label: 'Active' }, { value: 'all', label: 'All' }]} />
	{/snippet}
	{#snippet bulk(n)}
		<Button size="sm" icon={Check} onclick={() => apply('acknowledge')}>Acknowledge {n}</Button>
		<Button size="sm" icon={CheckCheck} onclick={() => apply('resolve')}>Resolve {n}</Button>
	{/snippet}
	{#snippet empty()}
		<EmptyState compact title={view === 'active' ? 'No open alerts' : 'No alerts yet'} description={view === 'active' ? 'Nothing on this agent needs a look.' : undefined} />
	{/snippet}
</DataTable>

<div class="mt-4 grid gap-4 xl:grid-cols-2">
	<section class="card" aria-label="Maintenance windows and snoozes">
		<header class="border-border flex min-h-12 items-center justify-between gap-2 border-b px-4 py-2">
			<h2 class="panel-title">Maintenance and snoozes</h2>
			{#if can('technician')}<Button size="sm" icon={BellOff} onclick={() => (snoozing = true)}>Snooze</Button>{/if}
		</header>
		{#if mutes.data?.length}
			<ul class="divide-border divide-y">
				{#each mutes.data as m (m.id)}
					<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
						<div class="min-w-0 flex-1">
							<div class="flex flex-wrap items-center gap-2">
								<span>{describeMute(m, datetime)}</span>
								{#if m.active}<Badge tone="warning">Now</Badge>{/if}
							</div>
							<div class="text-muted text-xs">
								{m.agent_id ? 'This agent' : m.site_id ? `Site ${m.target_name}` : `Client ${m.target_name}`}{m.reason ? ` · ${m.reason}` : ''}{m.created_by_name ? ` · ${m.created_by_name}` : ''}
							</div>
						</div>
						{#if can('technician')}<Button size="sm" variant="ghost" onclick={() => endMute(m)}>{m.ends_at ? 'End' : 'Remove'}</Button>{/if}
					</li>
				{/each}
			</ul>
		{:else if !mutes.loading}
			<EmptyState compact title="Alerts aren't held back" description="Snooze before planned work, or add a weekly window (at the bottom of the Alerts page) for regular reboots and backups." />
		{/if}
	</section>

	<section class="card" aria-labelledby="agent-alert-policies">
		<header class="panel-head"><h2 id="agent-alert-policies" class="panel-title">Alert policies</h2></header>
		<div class="space-y-3 p-4 text-sm">
			<p class="text-muted">Which alert policies watch {hostname} comes from the policy set it uses. Its Policy section lists them and where each is set; one can be left out for this device there.</p>
			<Button size="sm" icon={ShieldCheck} href="?tab=policy">Policies on this device</Button>
		</div>
	</section>
</div>

{#if snoozing}<MuteDialog target={{ agent_id: agentId, name: hostname }} onclose={() => (snoozing = false)} onsaved={() => { mutes.reload(); onchange?.(); }} />{/if}
