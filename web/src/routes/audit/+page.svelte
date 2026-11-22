<script lang="ts">
	import { Download, History } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import type { AuditRow } from '#lib/types.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';

	// The date filters are local days (`from` is the start of one, `to` the end of one).
	const dayStart = (d: string) => (d ? new Date(`${d}T00:00:00`).toISOString() : '');
	const dayEnd = (d: string) => (d ? new Date(`${d}T23:59:59.999`).toISOString() : '');
	const filters = () => ({ action: param('action'), user_id: param('user'), from: dayStart(param('from')), to: dayEnd(param('to')) });
	const list = paged<AuditRow>(() => `/audit${qs(filters())}`);
	// The export takes the same filters and covers every match, not just this page.
	const exportHref = (format: 'csv' | 'jsonl') => `/api/audit/export${qs({ ...filters(), format })}`;
	const users = resource(() => api.get<{ id: string; name: string; email: string }[]>('/users'));

	const groups = [
		['', 'All actions'],
		['auth.', 'Sign-ins and accounts'],
		['user.', 'Users'],
		['client.', 'Clients'],
		['site.', 'Sites'],
		['enrollment_token.', 'Enrollment tokens'],
		['agent.', 'Agents and updates'],
		['job.', 'Jobs'],
		['shell.', 'Terminal sessions'],
		['script.', 'Scripts'],
		['settings.', 'Company settings'],
		['siem.', 'SIEM destinations'],
		['audit.', 'Audit log exports'],
		['api.', 'API key requests']
	];
	const targetHref = (r: AuditRow) =>
		r.target_id && ({ agent: `/agents/${r.target_id}`, client: `/clients/${r.target_id}`, script: `/scripts/${r.target_id}` } as Record<string, string>)[r.target_type ?? ''];
	let open = $state<number | null>(null);
</script>

<PageHeader title="Audit log" count={list.data ? `${list.data.total}${list.data.total_exact ? '' : '+'}` : null} description="Every change made through the dashboard or API, and agent update results.">
	{#snippet actions()}
		<Button href={exportHref('csv')} download icon={Download}>Export CSV</Button>
		<Button href={exportHref('jsonl')} download icon={Download}>Export JSON Lines</Button>
	{/snippet}
</PageHeader>

{#if list.error && !list.data}
	<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
{:else}
	{#snippet timeCell(r: AuditRow)}<time class="text-muted text-xs whitespace-nowrap" datetime={r.ts} title={datetime(r.ts)}>{ago(r.ts)}</time>{/snippet}
	{#snippet userCell(r: AuditRow)}{r.user_name ?? 'System'}{/snippet}
	{#snippet actionCell(r: AuditRow)}<code class="text-xs">{r.action}</code>{/snippet}
	{#snippet targetCell(r: AuditRow)}
		{@const href = targetHref(r)}
		{#if href}<a class="text-muted hover:text-fg text-xs hover:underline" {href}>{r.target_type}</a>{:else}<span class="text-muted text-xs">{r.target_type ?? ''}</span>{/if}
	{/snippet}
	{#snippet detailsCell(r: AuditRow)}
		{#if Object.keys(r.details).length}
			{@const json = JSON.stringify(r.details)}
			<button class="text-muted hover:text-fg block max-w-md text-left font-mono text-xs {open === r.id ? 'whitespace-pre-wrap break-all' : 'truncate'}" onclick={() => (open = open === r.id ? null : r.id)} aria-expanded={open === r.id}>
				{open === r.id ? JSON.stringify(r.details, null, 2) : json}
			</button>
		{/if}
	{/snippet}

	<DataTable
		id="audit"
		caption="Audit log"
		rows={list.rows}
		key={(r) => String(r.id)}
		loading={list.loading}
		busy={list.busy}
		columns={[
			{ id: 'ts', label: 'When', cell: timeCell, hideable: false },
			{ id: 'user', label: 'User', cell: userCell },
			{ id: 'action', label: 'Action', cell: actionCell, hideable: false },
			{ id: 'target', label: 'Target', cell: targetCell, from: 'sm' },
			{ id: 'details', label: 'Details', cell: detailsCell, from: 'md' }
		] satisfies Column<AuditRow>[]}
	>
		{#snippet toolbar()}
			<Select aria-label="Action" class="w-auto" value={param('action')} onchange={(e) => setParams({ action: e.currentTarget.value })} options={groups.map(([value, label]) => ({ value, label }))} />
			<Select
				aria-label="User"
				class="w-auto"
				value={param('user')}
				onchange={(e) => setParams({ user: e.currentTarget.value })}
				options={[{ value: '', label: 'Any user' }, ...(users.data ?? []).map((u) => ({ value: u.id, label: u.name || u.email }))]}
			/>
			<Input type="date" aria-label="From" class="w-auto" value={param('from')} max={param('to') || undefined} onchange={(e) => setParams({ from: e.currentTarget.value })} />
			<Input type="date" aria-label="To" class="w-auto" value={param('to')} min={param('from') || undefined} onchange={(e) => setParams({ to: e.currentTarget.value })} />
		{/snippet}
		{#snippet empty()}<EmptyState icon={History} compact title="No entries match" />{/snippet}
		{#snippet footer()}
			{#if list.data}
				<Pagination
					shown={list.rows.length}
					total={list.data.total}
					exact={list.data.total_exact}
					hasPrev={!!list.data.prev}
					hasNext={!!list.data.next}
					pageSize={list.pageSize}
					onprev={list.prev}
					onnext={list.next}
					onfirst={list.first}
					onpagesize={list.setPageSize}
				/>
			{/if}
		{/snippet}
	</DataTable>
{/if}
