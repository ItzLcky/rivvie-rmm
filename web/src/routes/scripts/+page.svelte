<script lang="ts">
	import { FileCode2, Plus, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, interpreterLabel } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, currentClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { Script } from '#lib/types.js';
	import { param, setParams, sortState } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';

	const res = resource(() => api.get<Script[]>('/scripts'));
	const sort = sortState('name');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const interp = $derived(param('interpreter'));
	const scoped = $derived(currentClient());

	const keyed: Record<string, (s: Script) => string | number> = {
		name: (s) => s.name.toLowerCase(),
		scope: (s) => (s.client_name ?? '').toLowerCase(),
		interpreter: (s) => s.interpreter,
		timeout: (s) => s.timeout_secs,
		updated: (s) => s.updated_at
	};
	const rows = $derived.by(() => {
		const f = param('q').toLowerCase();
		const cid = clientId();
		const list = (res.data ?? []).filter(
			(s) =>
				(!f || `${s.name} ${s.description}`.toLowerCase().includes(f)) &&
				(!interp || s.interpreter === interp) &&
				// A client scope shows MSP-wide scripts plus that client's own.
				(!cid || !s.client_id || s.client_id === cid)
		);
		const k = keyed[sort.key] ?? keyed.name;
		const sign = sort.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => (k(a) < k(b) ? -sign : k(a) > k(b) ? sign : 0));
	});
	const canCreate = $derived(can('admin') || (can('technician') && clients.list.length > 0));
</script>

<PageHeader title="Scripts" count={res.data ? rows.length : null} description={scoped ? `MSP-wide scripts, plus scripts for ${scoped.name} only.` : undefined}>
	{#snippet actions()}
		{#if canCreate}<Button variant="primary" icon={Plus} href="/scripts/new">New script</Button>{/if}
	{/snippet}
</PageHeader>

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	{#snippet nameCell(s: Script)}
		<a class="hover:text-accent font-medium" href="/scripts/{s.id}">{s.name}</a>
		{#if s.description}<div class="text-muted max-w-md truncate text-xs">{s.description}</div>{/if}
	{/snippet}
	{#snippet scopeCell(s: Script)}{#if s.client_name}<Badge>{s.client_name}</Badge>{:else}<Badge tone="accent">All clients</Badge>{/if}{/snippet}
	{#snippet interpCell(s: Script)}{interpreterLabel(s.interpreter)}{/snippet}
	{#snippet timeoutCell(s: Script)}{s.timeout_secs}s{/snippet}
	{#snippet updatedCell(s: Script)}<span class="text-muted text-xs">{ago(s.updated_at)}</span>{/snippet}

	<DataTable
		id="scripts"
		caption="Scripts"
		{rows}
		key={(s) => s.id}
		loading={res.loading}
		{sort}
		rowHref={(s) => `/scripts/${s.id}`}
		columns={[
			{ id: 'name', label: 'Name', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'scope', label: 'Scope', sort: 'scope', cell: scopeCell, from: 'sm' },
			{ id: 'interpreter', label: 'Interpreter', sort: 'interpreter', cell: interpCell, from: 'md' },
			{ id: 'timeout', label: 'Timeout', sort: 'timeout', cell: timeoutCell, align: 'right', from: 'lg' },
			{ id: 'updated', label: 'Updated', sort: 'updated', cell: updatedCell, from: 'md' }
		] satisfies Column<Script>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Name or description…" aria-label="Search scripts" class="w-full sm:w-64" bind:value={q} />
			<Select
				aria-label="Interpreter"
				class="w-auto"
				value={interp}
				onchange={(e) => setParams({ interpreter: e.currentTarget.value })}
				options={[{ value: '', label: 'Any interpreter' }, ...['bash', 'sh', 'powershell', 'cmd', 'python'].map((v) => ({ value: v, label: interpreterLabel(v) }))]}
			/>
		{/snippet}
		{#snippet empty()}
			{#if param('q') || interp}
				<EmptyState compact title="No scripts match" />
			{:else}
				<EmptyState icon={FileCode2} title="No saved scripts" description="Save scripts you run often. Run them on one agent, a selection, or from the command palette.">
					{#snippet action()}{#if canCreate}<Button variant="primary" icon={Plus} href="/scripts/new">New script</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</DataTable>
{/if}
