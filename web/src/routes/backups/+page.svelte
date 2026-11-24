<script lang="ts">
	import { DatabaseBackup, Search } from '@lucide/svelte';
	import { ago, bytes, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import { backupLabel, backupTone, providerLabels, type BackupJob } from '#lib/uptime.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Select from '#lib/ui/Select.svelte';

	const scoped = $derived(currentClient());
	const sort = sortState('result');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null, after: null, before: null }), 250);
		return () => clearTimeout(t);
	});
	const jobs = paged<BackupJob>(() => `/backups${qs({ client_id: clientId(), result: param('result'), provider: param('provider'), alerting: param('alerting') || undefined, q: param('q'), sort: sort.key, dir: sort.dir })}`);
	liveReload(() => jobs.reload(), (e) => e.type === 'alert' || e.type === 'backups', { debounceMs: 2000, pollMs: 60000 });
	const filtered = $derived(!!(param('q') || param('result') || param('provider') || param('alerting')));
</script>

<PageHeader title="Backups" description="The last result of the backup jobs on every device: Windows Server Backup, Veeam, restic, Borg, Time Machine and backup files.">
	{#snippet actions()}<Button href="/policies">Alert policies</Button>{/snippet}
</PageHeader>

{#if jobs.error && !jobs.data}
	<div class="card"><ErrorState error={jobs.error} onretry={() => jobs.reload()} /></div>
{:else}
	{#snippet deviceCell(j: BackupJob)}
		<a class="hover:text-accent font-medium whitespace-nowrap" href="/agents/{j.agent_id}">{j.hostname}</a>
		<div class="text-muted text-xs whitespace-nowrap">{scoped ? j.site_name : `${j.client_name} › ${j.site_name}`}{j.online ? '' : ' · offline'}</div>
	{/snippet}
	{#snippet productCell(j: BackupJob)}<span class="whitespace-nowrap">{providerLabels[j.provider] ?? j.provider}</span>{/snippet}
	{#snippet jobCell(j: BackupJob)}
		<span class="block max-w-80 truncate" title={j.job}>{j.job}</span>
		{#if j.message && j.last_result !== 'success'}<div class="text-muted max-w-80 truncate text-xs" title={j.message}>{j.message}</div>{/if}
	{/snippet}
	{#snippet successCell(j: BackupJob)}
		<span class="whitespace-nowrap" title={datetime(j.last_success_at)}>{j.last_success_at ? ago(j.last_success_at) : 'never'}</span>
		{#if j.size_bytes}<div class="text-muted text-xs">{bytes(j.size_bytes)}</div>{/if}
	{/snippet}
	{#snippet resultCell(j: BackupJob)}
		<Badge tone={backupTone[j.last_result]}>{backupLabel[j.last_result]}</Badge>
		{#if j.alerting}<div class="text-danger mt-0.5 text-xs">alert open</div>{/if}
	{/snippet}
	{#snippet runCell(j: BackupJob)}<span class="text-muted whitespace-nowrap" title={datetime(j.last_run_at)}>{j.last_run_at ? ago(j.last_run_at) : '–'}</span>{/snippet}

	<DataTable
		id="backups"
		caption="Backup jobs"
		activeFilters={[param('result'), param('provider'), param('alerting')].filter(Boolean).length}
		rows={jobs.rows}
		key={(j) => `${j.agent_id}/${j.provider}/${j.job}`}
		loading={jobs.loading && !jobs.data}
		busy={jobs.busy}
		{sort}
		columns={[
			{ id: 'device', label: 'Device', sort: 'hostname', cell: deviceCell, hideable: false },
			{ id: 'product', label: 'Product', cell: productCell, from: 'md' },
			{ id: 'job', label: 'Job', sort: 'job', cell: jobCell, from: 'sm' },
			{ id: 'success', label: 'Last success', sort: 'last_success', cell: successCell },
			{ id: 'run', label: 'Last run', sort: 'last_run', cell: runCell, from: 'lg' },
			{ id: 'result', label: 'Result', sort: 'result', cell: resultCell }
		] satisfies Column<BackupJob>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Device or job…" aria-label="Search backups" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			<Select aria-label="Result" class="w-full sm:w-auto" value={param('result')} onchange={(e) => setParams({ result: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any result' }, ...Object.entries(backupLabel).map(([value, label]) => ({ value, label }))]} />
			<Select aria-label="Product" class="w-full sm:w-auto" value={param('provider')} onchange={(e) => setParams({ provider: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any product' }, ...Object.entries(providerLabels).map(([value, label]) => ({ value, label }))]} />
			<Select aria-label="Alerts" class="w-full sm:w-auto" value={param('alerting')} onchange={(e) => setParams({ alerting: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'With or without alerts' }, { value: 'true', label: 'With an open alert' }]} />
		{/snippet}
		{#snippet empty()}
			{#if filtered}
				<EmptyState title="No backup jobs match" description="Try other filters.">
					{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, result: null, provider: null, alerting: null }); }}>Clear filters</Button>{/snippet}
				</EmptyState>
			{:else}
				<EmptyState icon={DatabaseBackup} title="No backup jobs reported yet" description="Add a Backups alert item to a policy set: its devices then read their backup jobs every hour.">
					{#snippet action()}<Button size="sm" variant="primary" href="/policies">Open policies</Button>{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
		{#snippet footer()}
			{#if jobs.data && (jobs.data.next || jobs.data.prev)}
				<Pagination shown={jobs.rows.length} total={jobs.data.total} hasPrev={!!jobs.data.prev} hasNext={!!jobs.data.next} pageSize={jobs.pageSize} onprev={jobs.prev} onnext={jobs.next} onfirst={jobs.first} onpagesize={jobs.setPageSize} />
			{/if}
		{/snippet}
	</DataTable>
{/if}
