<script lang="ts">
	import { HardDrive, Search } from '@lucide/svelte';
	import { kindLabel, volumeStatusLabel, volumeStatusTone, type DiskVolume } from '#lib/devicesec.js';
	import { ago, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Select from '#lib/ui/Select.svelte';

	/** Every fixed volume's encryption across the fleet (or the selected client). */
	const scoped = $derived(currentClient());
	const sort = sortState('status');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null, after: null, before: null }), 250);
		return () => clearTimeout(t);
	});
	const vols = paged<DiskVolume>(() =>
		`/disk-encryption${qs({ client_id: clientId(), status: param('status'), escrowed: param('escrowed') || undefined, os_only: param('os_only') || undefined, q: param('q'), sort: sort.key, dir: sort.dir })}`
	);
	liveReload(() => vols.reload(), (e) => e.type === 'security' || e.type === 'alert', { debounceMs: 2000, pollMs: 60000 });
	const filtered = $derived(!!(param('q') || param('status') || param('escrowed') || param('os_only')));
</script>

{#if vols.error && !vols.data}
	<div class="card"><ErrorState error={vols.error} onretry={() => vols.reload()} /></div>
{:else}
	{#snippet deviceCell(v: DiskVolume)}
		<a class="hover:text-accent font-medium whitespace-nowrap" href="/agents/{v.agent_id}?tab=inventory">{v.hostname}</a>
		<div class="text-muted text-xs whitespace-nowrap">{scoped ? v.site_name : `${v.client_name} › ${v.site_name}`}{v.online ? '' : ' · offline'}</div>
	{/snippet}
	{#snippet volumeCell(v: DiskVolume)}
		<span class="font-mono text-xs">{v.volume_id}</span>
		<div class="text-muted text-xs">{v.role === 'os' ? 'System' : 'Data'}</div>
	{/snippet}
	{#snippet kindCell(v: DiskVolume)}{kindLabel[v.kind]}{#if v.method}<div class="text-muted text-xs">{v.method}</div>{/if}{/snippet}
	{#snippet statusCell(v: DiskVolume)}
		<Badge tone={volumeStatusTone[v.status]}>{volumeStatusLabel[v.status]}</Badge>
		{#if v.alerting}<div class="text-danger mt-0.5 text-xs">alert open</div>{/if}
	{/snippet}
	{#snippet escrowCell(v: DiskVolume)}
		{#if v.kind !== 'bitlocker'}<span class="text-muted">–</span>{:else if v.escrowed}<span title={datetime(v.escrowed_at)}>Escrowed {v.escrowed_at ? ago(v.escrowed_at) : ''}</span>{:else}<Badge tone="warning">{v.recovery_protector_id ? 'Not escrowed' : 'No recovery password'}</Badge>{/if}
	{/snippet}
	{#snippet updatedCell(v: DiskVolume)}<span class="text-muted whitespace-nowrap" title={datetime(v.updated_at)}>{ago(v.updated_at)}</span>{/snippet}

	<DataTable
		id="disk-encryption"
		caption="Disk encryption"
		activeFilters={[param('status'), param('escrowed'), param('os_only')].filter(Boolean).length}
		rows={vols.rows}
		key={(v) => `${v.agent_id}/${v.volume_id}`}
		loading={vols.loading && !vols.data}
		busy={vols.busy}
		{sort}
		columns={[
			{ id: 'device', label: 'Device', sort: 'hostname', cell: deviceCell, hideable: false },
			{ id: 'volume', label: 'Volume', sort: 'volume', cell: volumeCell },
			{ id: 'kind', label: 'Encryption', cell: kindCell, from: 'md' },
			{ id: 'status', label: 'Status', sort: 'status', cell: statusCell },
			{ id: 'escrow', label: 'Recovery key', cell: escrowCell, from: 'sm' },
			{ id: 'updated', label: 'Reported', sort: 'updated', cell: updatedCell, from: 'lg' }
		] satisfies Column<DiskVolume>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} placeholder="Device…" aria-label="Search devices" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			<Select aria-label="Status" class="w-full sm:w-auto" value={param('status')} onchange={(e) => setParams({ status: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any status' }, ...Object.entries(volumeStatusLabel).map(([value, label]) => ({ value, label }))]} />
			<Select aria-label="Recovery key" class="w-full sm:w-auto" value={param('escrowed')} onchange={(e) => setParams({ escrowed: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any recovery key' }, { value: 'true', label: 'Escrowed' }, { value: 'false', label: 'Not escrowed' }]} />
			<Select aria-label="Volumes" class="w-full sm:w-auto" value={param('os_only')} onchange={(e) => setParams({ os_only: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Every volume' }, { value: 'true', label: 'System volumes' }]} />
		{/snippet}
		{#snippet empty()}
			{#if filtered}
				<EmptyState title="No volumes match" description="Try other filters.">
					{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, status: null, escrowed: null, os_only: null }); }}>Clear filters</Button>{/snippet}
				</EmptyState>
			{:else}
				<EmptyState icon={HardDrive} title="No disk encryption reported yet" description="Agents report BitLocker, FileVault and LUKS state when they connect." />
			{/if}
		{/snippet}
		{#snippet footer()}
			{#if vols.data && (vols.data.next || vols.data.prev)}
				<Pagination shown={vols.rows.length} total={vols.data.total} hasPrev={!!vols.data.prev} hasNext={!!vols.data.next} pageSize={vols.pageSize} onprev={vols.prev} onnext={vols.next} onfirst={vols.first} onpagesize={vols.setPageSize} />
			{/if}
		{/snippet}
	</DataTable>
{/if}
