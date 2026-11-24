<script lang="ts">
	import { Search, Smartphone } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { complianceLabel, complianceTone, type MdmDevice, type MdmSummary } from '#lib/identity.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Status from '#lib/components/Status.svelte';

	/** The "Mobile and Intune" tab: the client's Intune devices, read-only, and the two gap lists. */
	let { clientId, clientName }: { clientId: string; clientName: string } = $props();

	const summary = resource(() => api.get<MdmSummary>(`/clients/${clientId}/mdm/summary`));
	const sort = sortState('compliance');
	let q = $state(param('mq'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ mq: v.trim() || null, after: null, before: null }), 250);
		return () => clearTimeout(t);
	});
	const devices = paged<MdmDevice>(
		() => `/clients/${clientId}/mdm/devices${qs({ compliance: param('mc'), unmatched: param('mu') || undefined, q: param('mq'), sort: sort.key, dir: sort.dir })}`
	);
	const filtered = $derived(!!(param('mq') || param('mc') || param('mu')));
</script>

<Async res={summary}>
	{#snippet children(s)}
		{#if !s.sources}
			<div class="card">
				<EmptyState icon={Smartphone} title="Intune isn’t read for {clientName}" description="Add the client’s Entra ID tenant on the Users tab and switch on “Also read Intune devices”. Devices are only read, never changed." />
			</div>
		{:else}
			<div class="space-y-4">
				<div class="grid gap-3 sm:grid-cols-4">
					<div class="card px-4 py-3"><div class="text-muted text-xs">In Intune</div><div class="text-xl font-semibold">{s.total}</div></div>
					<div class="card px-4 py-3"><div class="text-muted text-xs">Compliant</div><div class="text-success text-xl font-semibold">{s.by_compliance.compliant ?? 0}</div></div>
					<div class="card px-4 py-3"><div class="text-muted text-xs">Not compliant</div><div class="text-danger text-xl font-semibold">{(s.by_compliance.noncompliant ?? 0) + (s.by_compliance.error ?? 0)}</div></div>
					<div class="card px-4 py-3"><div class="text-muted text-xs">In Intune, no agent</div><div class="text-xl font-semibold">{s.unmatched}</div></div>
				</div>

				{#snippet nameCell(d: MdmDevice)}
					<span class="font-medium">{d.name || '–'}</span>
					<div class="text-muted text-xs">{[d.manufacturer, d.model].filter(Boolean).join(' ') || '–'}{d.serial ? ` · ${d.serial}` : ''}</div>
				{/snippet}
				{#snippet osCell(d: MdmDevice)}<span class="whitespace-nowrap">{d.os} {d.os_version}</span>{/snippet}
				{#snippet complianceCell(d: MdmDevice)}
					<Badge tone={complianceTone(d.compliance)}>{complianceLabel[d.compliance] ?? d.compliance}</Badge>
					{#if d.encrypted === false}<div class="text-warning mt-0.5 text-xs">not encrypted</div>{/if}
				{/snippet}
				{#snippet ownerCell(d: MdmDevice)}
					<span class="block max-w-56 truncate">{d.user_upn || '–'}</span>
					<div class="text-muted text-xs">{d.ownership === 'company' ? 'Company' : d.ownership === 'personal' ? 'Personal' : 'Unknown'} device</div>
				{/snippet}
				{#snippet syncCell(d: MdmDevice)}<span class="text-muted whitespace-nowrap" title={datetime(d.last_sync_at)}>{d.last_sync_at ? ago(d.last_sync_at) : '–'}</span>{/snippet}
				{#snippet agentCell(d: MdmDevice)}
					{#if d.agent_id}<a class="hover:text-accent inline-flex items-center gap-1.5 whitespace-nowrap" href="/agents/{d.agent_id}"><Status online={!!d.agent_online} />{d.agent_hostname}</a>{:else}<span class="text-muted">No agent</span>{/if}
				{/snippet}
				<DataTable
					id="mdm-devices"
					caption="{clientName}’s Intune devices"
					rows={devices.rows}
					key={(d) => d.id}
					loading={devices.loading && !devices.data}
					busy={devices.busy}
					{sort}
					activeFilters={[param('mc'), param('mu')].filter(Boolean).length}
					columns={[
						{ id: 'name', label: 'Device', sort: 'name', cell: nameCell, hideable: false },
						{ id: 'os', label: 'OS', cell: osCell, from: 'md' },
						{ id: 'compliance', label: 'Compliance', sort: 'compliance', cell: complianceCell },
						{ id: 'owner', label: 'User', sort: 'user', cell: ownerCell, from: 'lg' },
						{ id: 'sync', label: 'Last check-in', sort: 'last_sync', cell: syncCell, from: 'sm' },
						{ id: 'agent', label: 'Agent', cell: agentCell, from: 'md' }
					] satisfies Column<MdmDevice>[]}
				>
					{#snippet toolbar()}
						<Input icon={Search} data-search placeholder="Device, user or serial…" aria-label="Search devices" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
					{/snippet}
					{#snippet filters()}
						<Select aria-label="Compliance" class="w-full sm:w-auto" value={param('mc')} onchange={(e) => setParams({ mc: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any compliance' }, ...Object.entries(complianceLabel).map(([value, label]) => ({ value, label }))]} />
						<Select aria-label="Agent" class="w-full sm:w-auto" value={param('mu')} onchange={(e) => setParams({ mu: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'With or without an agent' }, { value: 'true', label: 'In Intune, no agent' }]} />
					{/snippet}
					{#snippet empty()}
						{#if filtered}
							<EmptyState title="No devices match" description="Try other filters.">
								{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ mq: null, mc: null, mu: null }); }}>Clear filters</Button>{/snippet}
							</EmptyState>
						{:else}
							<EmptyState icon={Smartphone} title="No Intune devices" description="None were read at the last sync." />
						{/if}
					{/snippet}
					{#snippet footer()}
						{#if devices.data && (devices.data.next || devices.data.prev)}
							<Pagination shown={devices.rows.length} total={devices.data.total} hasPrev={!!devices.data.prev} hasNext={!!devices.data.next} pageSize={devices.pageSize} onprev={devices.prev} onnext={devices.next} onfirst={devices.first} onpagesize={devices.setPageSize} />
						{/if}
					{/snippet}
				</DataTable>

				<section class="card" aria-labelledby="gap-h">
					<header class="panel-head">
						<div class="min-w-0">
							<h2 id="gap-h" class="font-semibold">Agent, not in Intune</h2>
							<p class="text-muted text-xs">Windows and macOS workstations with our agent that Intune doesn’t list (matched by host name).</p>
						</div>
					</header>
					{#if s.agents_not_in_intune.length}
						<ul class="divide-border divide-y">
							{#each s.agents_not_in_intune as a (a.id)}
								<li class="flex items-center gap-2 px-5 py-2 text-sm">
									<Status online={a.online} />
									<a class="hover:text-accent font-medium" href="/agents/{a.id}">{a.hostname}</a>
									<span class="text-muted text-xs">{a.os_family}{a.online ? '' : ` · seen ${ago(a.last_seen_at)}`}</span>
								</li>
							{/each}
						</ul>
					{:else}
						<p class="text-muted px-5 py-3 text-sm">Every workstation with an agent is in Intune.</p>
					{/if}
					{#if s.agents_not_in_intune.length >= 500}<p class="hint px-5 pb-3">Showing the first {plural(500, 'device')}.</p>{/if}
				</section>
			</div>
		{/if}
	{/snippet}
</Async>
