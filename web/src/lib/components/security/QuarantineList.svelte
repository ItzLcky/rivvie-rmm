<script lang="ts">
	import type { Snippet } from 'svelte';
	import { RotateCcw, Trash2 } from '@lucide/svelte';
	import { ago, bytes, datetime } from '#lib/format.js';
	import { quarantineStateLabels } from '#lib/security.js';
	import { allowed } from '#lib/session.svelte.js';
	import type { QuarantineRow } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import { baseName, deleteQuarantined } from './quarantine.js';
	import RestoreDialog from './RestoreDialog.svelte';

	/** Quarantined files, with Restore and Delete for people who may respond. */
	let {
		id,
		rows,
		showAgent = false,
		loading = false,
		busy = false,
		toolbar,
		emptyTitle = 'Nothing in quarantine',
		onchanged
	}: {
		id: string;
		rows: QuarantineRow[];
		showAgent?: boolean;
		loading?: boolean;
		busy?: boolean;
		toolbar?: Snippet;
		emptyTitle?: string;
		onchanged?: () => void;
	} = $props();

	let restoring = $state<QuarantineRow | null>(null);
	const canRespond = $derived(allowed('security.respond'));

	async function remove(q: QuarantineRow) {
		if (await deleteQuarantined(q.agent_id, q.hostname, q)) onchanged?.();
	}
</script>

{#snippet fileCell(q: QuarantineRow)}
	<div class="font-medium break-all">{baseName(q.path)}</div>
	<div class="text-muted font-mono text-xs break-all">{q.path}</div>
	{#if q.reason}<div class="text-muted text-xs break-words">{q.reason}</div>{/if}
{/snippet}
{#snippet agentCell(q: QuarantineRow)}
	<a class="hover:text-accent font-medium" href="/agents/{q.agent_id}?tab=security">{q.hostname}</a>
	<div class="text-muted truncate text-xs">{q.client_name}</div>
{/snippet}
{#snippet hashCell(q: QuarantineRow)}
	<span class="text-muted font-mono text-xs" title={q.sha256}>{q.sha256.slice(0, 12)}…</span>
	<div class="text-muted text-xs tabular">{bytes(q.size)}</div>
{/snippet}
{#snippet whenCell(q: QuarantineRow)}
	<span class="whitespace-nowrap" title={datetime(q.quarantined_at)}>{ago(q.quarantined_at)}</span>
	{#if q.state !== 'quarantined'}<div class="text-muted text-xs">{quarantineStateLabels[q.state]} {ago(q.updated_at)}</div>{/if}
{/snippet}
{#snippet stateCell(q: QuarantineRow)}
	{#if q.state === 'quarantined'}<span class="text-muted">{quarantineStateLabels[q.state]}</span>{:else if q.state === 'restored'}<Badge tone="warning">Restored</Badge>{:else}<Badge>{quarantineStateLabels[q.state]}</Badge>{/if}
{/snippet}
{#snippet actionsCell(q: QuarantineRow)}
	{#if canRespond && q.state === 'quarantined'}
		<Menu
			label="Actions for {baseName(q.path)}"
			items={[
				{ label: 'Restore…', icon: RotateCcw, onSelect: () => (restoring = q) },
				{ separator: true },
				{ label: 'Delete permanently…', icon: Trash2, danger: true, onSelect: () => remove(q) }
			]}
		/>
	{/if}
{/snippet}

{#snippet heading()}<h2 class="text-sm font-semibold">Quarantine</h2>{/snippet}

<DataTable
	{id}
	caption="Quarantined files"
	{rows}
	key={(q) => q.id}
	{loading}
	{busy}
	scroll={false}
	toolbar={toolbar ?? heading}
	columns={[
		{ id: 'file', label: 'File', cell: fileCell, hideable: false },
		...(showAgent ? [{ id: 'agent', label: 'Agent', cell: agentCell, from: 'sm' } satisfies Column<QuarantineRow>] : []),
		{ id: 'hash', label: 'SHA-256', cell: hashCell, from: 'lg' },
		{ id: 'when', label: 'Quarantined', cell: whenCell, from: 'md' },
		{ id: 'state', label: 'State', cell: stateCell, from: 'sm' },
		{ id: 'actions', label: '', cell: actionsCell, hideable: false, align: 'right', class: 'w-12' }
	] satisfies Column<QuarantineRow>[]}
>
	{#snippet empty()}
		<EmptyState compact title={emptyTitle} description="Files our sensor or a technician quarantines are kept here, in a protected store on the machine, until restored or deleted." />
	{/snippet}
</DataTable>

{#if restoring}
	<RestoreDialog agentId={restoring.agent_id} hostname={restoring.hostname} id={restoring.id} path={restoring.path} onclose={() => (restoring = null)} ondone={onchanged} />
{/if}
