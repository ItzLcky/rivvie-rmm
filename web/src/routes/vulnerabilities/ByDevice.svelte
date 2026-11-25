<script lang="ts">
	import { Search, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';

	type Row = {
		agent_id: string; hostname: string; online: boolean; os_family: string; os_name: string; client_name: string; site_name: string; ecosystem: string | null;
		critical: number; high: number; open: number; kev: number; fixable: number; evaluated_at: string | null;
	};
	const scoped = $derived(currentClient());
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const rows = resource(() => api.get<Row[]>(`/vulnerabilities/agents${qs({ client_id: clientId(), q: param('q') })}`));
	const count = (n: number, tone: string) => (n ? `font-semibold tabular ${tone}` : 'text-muted tabular');
</script>

{#if rows.error && !rows.data}
	<div class="card"><ErrorState error={rows.error} onretry={() => rows.reload()} /></div>
{:else}
	{#snippet deviceCell(r: Row)}
		<a class="hover:text-accent font-medium whitespace-nowrap" href="/agents/{r.agent_id}?tab=vulnerabilities">{r.hostname}</a>
		<div class="text-muted text-xs whitespace-nowrap">{scoped ? r.site_name : `${r.client_name} › ${r.site_name}`}{r.online ? '' : ' · offline'}</div>
	{/snippet}
	{#snippet osCell(r: Row)}<span class="whitespace-nowrap">{r.os_name}</span><div class="text-muted text-xs">{r.ecosystem}</div>{/snippet}
	{#snippet critCell(r: Row)}<span class={count(r.critical, 'text-danger')}>{num(r.critical)}</span>{/snippet}
	{#snippet highCell(r: Row)}<span class={count(r.high, 'text-warning')}>{num(r.high)}</span>{/snippet}
	{#snippet kevCell(r: Row)}<span class={count(r.kev, 'text-danger')}>{num(r.kev)}</span>{/snippet}
	{#snippet openCell(r: Row)}<span class="tabular">{num(r.open)}</span><div class="text-muted text-xs">{num(r.fixable)} fixable</div>{/snippet}
	{#snippet checkedCell(r: Row)}<span class="text-muted whitespace-nowrap" title={datetime(r.evaluated_at)}>{r.evaluated_at ? ago(r.evaluated_at) : '–'}</span>{/snippet}
	<DataTable
		id="vuln-devices"
		caption="Devices with vulnerabilities"
		rows={rows.data ?? []}
		key={(r) => r.agent_id}
		loading={rows.loading && !rows.data}
		rowHref={(r) => `/agents/${r.agent_id}?tab=vulnerabilities`}
		columns={[
			{ id: 'device', label: 'Device', cell: deviceCell, hideable: false },
			{ id: 'os', label: 'System', cell: osCell, from: 'md' },
			{ id: 'critical', label: 'Critical', cell: critCell, align: 'right' },
			{ id: 'high', label: 'High', cell: highCell, align: 'right' },
			{ id: 'kev', label: 'Exploited', cell: kevCell, align: 'right', from: 'sm' },
			{ id: 'open', label: 'All open', cell: openCell, align: 'right', from: 'sm' },
			{ id: 'checked', label: 'Checked', cell: checkedCell, from: 'lg' }
		] satisfies Column<Row>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Device…" aria-label="Search devices" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet empty()}<EmptyState icon={ShieldCheck} title="No device has open vulnerabilities" description="Accepted risks don’t count here." />{/snippet}
	</DataTable>
{/if}
