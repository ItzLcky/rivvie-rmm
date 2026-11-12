<script lang="ts">
	import { RefreshCw, Search, Skull } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentDetail, Process } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	let { agent }: { agent: AgentDetail } = $props();
	const capable = $derived(agent.capabilities?.includes('tools'));
	const res = resource(() => (agent.online && capable ? api.get<{ processes: Process[] }>(`/agents/${agent.id}/processes`).then((r) => r.processes) : Promise.resolve(null)));
	let fetchedAt = $state<string | null>(null);
	$effect(() => {
		if (res.data) fetchedAt = new Date().toISOString();
	});

	let live = $state(false);
	$effect(() => {
		if (!live) return;
		const t = setInterval(() => !res.busy && res.reload(), 5000);
		return () => clearInterval(t);
	});

	let q = $state('');
	let sortBy = $state<{ key: string; dir: 'asc' | 'desc' }>({ key: 'cpu', dir: 'desc' });
	const sort = {
		get key() {
			return sortBy.key;
		},
		get dir() {
			return sortBy.dir;
		},
		toggle: (k: string) => (sortBy = { key: k, dir: sortBy.key === k ? (sortBy.dir === 'asc' ? 'desc' : 'asc') : k === 'name' || k === 'user' ? 'asc' : 'desc' })
	};
	const rows = $derived.by(() => {
		const needle = q.trim().toLowerCase();
		const list = (res.data ?? []).filter((p) => !needle || `${p.pid} ${p.name} ${p.user ?? ''} ${p.cmd ?? ''}`.toLowerCase().includes(needle));
		const k = sortBy.key as keyof Process;
		const sign = sortBy.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => {
			const x = a[k] ?? '';
			const y = b[k] ?? '';
			return sign * (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' }));
		});
	});

	async function kill(p: Process, tree: boolean) {
		const ok = await confirmAction({
			title: `Kill ${p.name} (${p.pid})${tree ? ' and its children' : ''}?`,
			message: `It's stopped at once, without a chance to save anything${tree ? '; everything it started goes too' : ''}. Recorded in the audit log.`,
			confirmLabel: 'Kill',
			danger: true
		});
		if (!ok) return;
		try {
			const r = await api.post<{ message: string }>(`/agents/${agent.id}/processes/${p.pid}/kill`, { tree, name: p.name });
			toast.success(r.message);
			res.reload();
		} catch (e) {
			toast.error(e);
		}
	}
</script>

{#snippet pidCell(p: Process)}<span class="text-muted font-mono text-xs tabular">{p.pid}</span>{/snippet}
{#snippet nameCell(p: Process)}
	<div class="flex items-center gap-2">
		<span class="font-medium">{p.name}</span>
		{#if p.protected}<Badge tone="neutral" title="System or agent process: the agent won't kill it">Protected</Badge>{/if}
	</div>
	{#if p.cmd}<div class="text-muted max-w-[40rem] truncate font-mono text-xs" title={p.cmd}>{p.cmd}</div>{/if}
{/snippet}
{#snippet userCell(p: Process)}<span class="text-muted">{p.user ?? '–'}</span>{/snippet}
{#snippet cpuCell(p: Process)}<span class="tabular">{p.cpu.toFixed(1)}%</span>{/snippet}
{#snippet memCell(p: Process)}<span class="tabular">{bytes(p.mem)}</span>{/snippet}
{#snippet startedCell(p: Process)}<span class="text-muted whitespace-nowrap" title={p.started_at ? datetime(p.started_at) : undefined}>{p.started_at ? ago(p.started_at) : '–'}</span>{/snippet}
{#snippet actionCell(p: Process)}
	{#if !p.protected}
		<Menu
			label="Actions for {p.name}"
			items={[
				{ label: 'Kill', icon: Skull, danger: true, onSelect: () => kill(p, false) },
				{ label: 'Kill with children', icon: Skull, danger: true, onSelect: () => kill(p, true) }
			]}
		/>
	{/if}
{/snippet}

{#if !capable}
	<div class="card"><EmptyState title="The process list needs a newer agent" description="This agent's version (v{agent.agent_version}) can't list processes. Update the agent, then reopen this page." /></div>
{:else if !agent.online}
	<div class="card"><EmptyState title="The agent is offline" description="Processes are read live from the machine; they show once it reconnects." /></div>
{:else if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	<DataTable
		id="agent-processes"
		caption="Processes on {agent.hostname}"
		rows={rows.slice(0, 1000)}
		key={(p) => String(p.pid)}
		loading={res.loading}
		busy={res.busy && !live}
		{sort}
		columns={[
			{ id: 'pid', label: 'PID', sort: 'pid', cell: pidCell, class: 'w-20' },
			{ id: 'name', label: 'Process', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'user', label: 'User', sort: 'user', cell: userCell, from: 'md' },
			{ id: 'cpu', label: 'CPU', sort: 'cpu', cell: cpuCell, align: 'right' },
			{ id: 'mem', label: 'Memory', sort: 'mem', cell: memCell, align: 'right', from: 'sm' },
			{ id: 'started', label: 'Started', sort: 'started_at', cell: startedCell, align: 'right', from: 'lg' },
			{ id: 'actions', label: '', cell: actionCell, hideable: false, align: 'right', class: 'w-12' }
		] satisfies Column<Process>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Name, PID, user or command…" aria-label="Filter processes" class="min-w-0 flex-1 sm:w-72 sm:flex-none" bind:value={q} />
			<span class="text-muted text-xs">{num(res.data?.length ?? 0)} processes{fetchedAt ? ` · ${live ? 'refreshing every 5 s' : `read ${ago(fetchedAt)}`}` : ''}</span>
			<div class="ml-auto flex items-center gap-3">
				<Switch bind:checked={live}>Live</Switch>
				<Button size="sm" icon={RefreshCw} loading={res.busy && !live} onclick={() => res.reload()}>Refresh</Button>
			</div>
		{/snippet}
		{#snippet empty()}<EmptyState compact title={q ? 'No processes match' : 'No processes'} />{/snippet}
		{#snippet footer()}{#if rows.length > 1000}<p class="text-muted px-3 py-2 text-xs">Showing 1,000 of {num(rows.length)}; refine the filter.</p>{/if}{/snippet}
	</DataTable>
{/if}
