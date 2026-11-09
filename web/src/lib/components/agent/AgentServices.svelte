<script lang="ts">
	import { Play, RefreshCw, RotateCw, Search, Square } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { serviceTone } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AgentServices, ServiceInfo } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';

	let { agentId, online, hostname }: { agentId: string; online: boolean; hostname: string } = $props();
	const res = resource(() => api.get<AgentServices>(`/agents/${agentId}/services`));
	liveReload(() => res.reload(), (e) => (e.type === 'services' || e.type === 'alert') && e.agent_id === agentId, { debounceMs: 500, pollMs: 60000 });

	let q = $state('');
	let view = $state<'all' | 'running' | 'stopped' | 'problems'>('all');
	let sort = $state<{ key: string; dir: 'asc' | 'desc' }>({ key: 'name', dir: 'asc' });
	const sortState = {
		get key() {
			return sort.key;
		},
		get dir() {
			return sort.dir;
		},
		toggle: (k: string) => (sort = { key: k, dir: sort.key === k && sort.dir === 'asc' ? 'desc' : 'asc' })
	};
	const alerting = $derived(new Set(res.data?.alerting ?? []));
	const all = $derived(res.data?.services ?? []);
	// Problems: alerting, failed, or set to start automatically but not running.
	const problem = (s: ServiceInfo) => alerting.has(s.name) || s.state === 'failed' || (s.start_mode === 'auto' && s.state === 'stopped');
	const rows = $derived.by(() => {
		const f = q.trim().toLowerCase();
		const list = all.filter(
			(s) =>
				(!f || `${s.name} ${s.display_name}`.toLowerCase().includes(f)) &&
				(view === 'all' || (view === 'running' ? s.state === 'running' : view === 'stopped' ? s.state !== 'running' : problem(s)))
		);
		const k = sort.key as keyof ServiceInfo;
		const sign = sort.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => sign * String(a[k]).localeCompare(String(b[k]), undefined, { sensitivity: 'base', numeric: true }));
	});
	const problems = $derived(all.filter(problem).length);
	let pending = $state<string | null>(null);

	async function control(s: ServiceInfo, action: 'start' | 'stop' | 'restart') {
		if (action !== 'start') {
			const ok = await confirmAction({
				title: `${action === 'stop' ? 'Stop' : 'Restart'} ${s.display_name || s.name}?`,
				message: `On ${hostname}. Anything that depends on it may stop too.`,
				confirmLabel: action === 'stop' ? 'Stop service' : 'Restart service',
				danger: action === 'stop'
			});
			if (!ok) return;
		}
		pending = s.name;
		await attempt(async () => {
			const r = await api.post<{ ok: boolean; message: string }>(`/agents/${agentId}/services/control`, { name: s.name, action });
			if (r.ok) toast.success(`${s.display_name || s.name}: ${action === 'stop' ? 'stopped' : action === 'start' ? 'started' : 'restarted'}.`);
			else toast.error(`${s.display_name || s.name}: ${r.message}`);
		});
		pending = null;
		res.reload();
	}
	async function refresh() {
		await attempt(() => api.post(`/agents/${agentId}/services/refresh`), 'Asked the agent for a fresh list.');
	}
	const modes = { auto: 'Automatic', manual: 'Manual', disabled: 'Disabled', unknown: '–' };
</script>

{#snippet nameCell(s: ServiceInfo)}
	<span class="font-medium">{s.display_name || s.name}</span>
	{#if s.display_name && s.display_name !== s.name}<div class="text-muted font-mono text-xs">{s.name}</div>{/if}
{/snippet}
{#snippet stateCell(s: ServiceInfo)}
	<Badge tone={serviceTone[s.state]}>{s.state}</Badge>
	{#if alerting.has(s.name)}<Badge tone="danger">Alert</Badge>{/if}
{/snippet}
{#snippet modeCell(s: ServiceInfo)}<span class="text-muted">{modes[s.start_mode]}</span>{/snippet}
{#snippet actionCell(s: ServiceInfo)}
	{#if can('technician')}
		<Menu
			label="Actions for {s.name}"
			items={[
				{ label: 'Start', icon: Play, disabled: !online || s.state === 'running' || pending !== null, onSelect: () => control(s, 'start') },
				{ label: 'Restart', icon: RotateCw, disabled: !online || pending !== null, onSelect: () => control(s, 'restart') },
				{ label: 'Stop', icon: Square, danger: true, disabled: !online || s.state === 'stopped' || pending !== null, onSelect: () => control(s, 'stop') }
			]}
		/>
	{/if}
{/snippet}

{#if res.data && res.data.services === null && !res.loading}
	<div class="card"><EmptyState title="No service list yet" description="Agents report their services after connecting. Older agents need an update first." /></div>
{:else}
	<DataTable
		id="agent-services"
		caption="Services"
		rows={rows.slice(0, 1000)}
		key={(s) => s.name}
		loading={res.loading}
		sort={sortState}
		scroll={false}
		columns={[
			{ id: 'name', label: 'Service', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'state', label: 'State', sort: 'state', cell: stateCell },
			{ id: 'start_mode', label: 'Startup', sort: 'start_mode', cell: modeCell, from: 'sm' },
			{ id: 'actions', label: '', cell: actionCell, hideable: false, align: 'right', class: 'w-12' }
		] satisfies Column<ServiceInfo>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Filter services…" aria-label="Filter services" class="w-full sm:w-64" bind:value={q} />
			<Segmented
				label="Show"
				value={view}
				onchange={(v) => (view = v)}
				options={[{ value: 'all', label: 'All', count: all.length }, { value: 'running', label: 'Running' }, { value: 'stopped', label: 'Stopped' }, { value: 'problems', label: 'Problems', count: problems }]}
			/>
			<span class="text-muted text-xs">Updated {ago(res.data?.services_at)}</span>
			<Button size="sm" icon={RefreshCw} class="ml-auto" disabled={!online} onclick={refresh}>Refresh</Button>
		{/snippet}
		{#snippet empty()}<EmptyState compact title={q || view !== 'all' ? 'No services match' : 'No services reported'} />{/snippet}
		{#snippet footer()}{#if rows.length > 1000}<p class="text-muted px-3 py-2 text-xs">Showing 1,000 of {num(rows.length)}; refine the filter.</p>{/if}{/snippet}
	</DataTable>
{/if}
