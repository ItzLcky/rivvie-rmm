<script lang="ts">
	import { Check, CheckCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { acknowledge, resolve } from '#lib/monitoring/alerts.svelte.js';
	import { kindLabels } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Alert, Page } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import AlertStateBadge from '#lib/components/AlertStateBadge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';

	let { agentId }: { agentId: string } = $props();
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
