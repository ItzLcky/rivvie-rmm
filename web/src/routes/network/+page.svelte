<script lang="ts">
	import { BellRing, Eye, EyeOff, Monitor, Network, Plus, Radar, Search, Settings, ShieldQuestion, Tag } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import DeviceDialog from '#lib/components/network/DeviceDialog.svelte';
	import MonitorDialog from '#lib/components/network/MonitorDialog.svelte';
	import { ago, datetime, duration, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import {
		discoveredLabel, discoveredTone, kindLabel, kindOptions, portLabel, stateLabel, stateTone,
		type Discovered, type NetDevice, type NetSummary
	} from '#lib/network.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';

	const tab = $derived(param('tab', 'devices') === 'discovered' ? 'discovered' : 'devices');
	const scoped = $derived(currentClient());
	const sort = sortState('name');

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});

	const summary = resource(() => api.get<NetSummary>(`/network/summary${qs({ client_id: clientId() })}`));
	const devices = resource(() => api.get<NetDevice[]>(`/network/devices${qs({ client_id: clientId(), site_id: param('site'), state: param('state'), kind: param('kind'), q: param('q') })}`));
	const dstate = $derived(param('found', 'unmanaged'));
	const found = resource(() => api.get<Discovered[]>(`/network/discovered${qs({ client_id: clientId(), site_id: param('site'), state: dstate, q: param('q'), limit: 2000 })}`));
	liveReload(() => { devices.reload(); summary.reload(); }, (e) => e.type === 'alert', { debounceMs: 2000 });

	function reloadAll() {
		devices.reload();
		found.reload();
		summary.reload();
	}

	const sites = $derived(scoped?.sites ?? []);
	function order<T>(rows: T[], get: (r: T) => string | number | null): T[] {
		const dir = sort.dir === 'desc' ? -1 : 1;
		return [...rows].sort((a, b) => {
			const x = get(a) ?? '';
			const y = get(b) ?? '';
			return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })) * dir;
		});
	}
	const devKeys: Record<string, (d: NetDevice) => string | number | null> = {
		name: (d) => d.name.toLowerCase(), kind: (d) => d.kind, state: (d) => ({ down: 0, unknown: 1, up: 2 })[d.state] ?? 3, host: (d) => d.host,
		site: (d) => `${d.client_name} ${d.site_name}`, cpu: (d) => d.cpu_percent, uptime: (d) => d.uptime_secs, polled: (d) => d.last_poll_at, alerts: (d) => d.open_alerts
	};
	const foundKeys: Record<string, (d: Discovered) => string | number | null> = {
		name: (d) => d.name.toLowerCase(), kind: (d) => d.kind, host: (d) => d.ip.split('.').map((n) => n.padStart(3, '0')).join('.'), vendor: (d) => d.vendor, site: (d) => `${d.client_name} ${d.site_name}`,
		seen: (d) => d.last_seen_at, first: (d) => d.first_seen_at, state: (d) => d.state
	};
	const devRows = $derived(order(devices.data ?? [], devKeys[sort.key] ?? devKeys.name));
	const foundRows = $derived(order(found.data ?? [], foundKeys[sort.key] ?? foundKeys.name));

	// --- actions on discovered hosts ---------------------------------------------------------
	let selected = $state(new Set<string>());
	let adding = $state(false);
	let monitoring = $state<Discovered | null>(null);
	let noting = $state<Discovered | null>(null);
	let note = $state('');
	let deploying = $state<{ host: Discovered; hint: { os: string; manageable: boolean; ways: { via: string; port: number; text: string }[] } } | null>(null);

	async function mark(ids: string[], status: 'ignored' | 'known' | 'unmanaged', text?: string) {
		const label = status === 'ignored' ? 'Ignored' : status === 'known' ? 'Marked as known' : 'Back on the list';
		if (await attempt(() => api.post('/network/discovered/bulk', { ids, status, note: text }), `${label}.`)) {
			selected = new Set();
			reloadAll();
		}
	}
	async function deploy(h: Discovered) {
		try {
			deploying = { host: h, hint: await api.get(`/network/discovered/${h.id}/deploy`) };
		} catch (err) {
			toast.error(err);
		}
	}
	async function setKind(h: Discovered, kind: string) {
		if (await attempt(() => api.patch(`/network/discovered/${h.id}`, { kind }))) found.reload();
	}

	const stateCounts = $derived(summary.data);
</script>

<PageHeader title="Network" description="What each site's designated agent finds on its network, and the switches, firewalls and printers it reads over SNMP.">
	{#snippet actions()}
		{#if can('technician')}<Button icon={Plus} onclick={() => (adding = true)}>Add device</Button>{/if}
		<Button icon={Settings} href={withClient('/network/settings')}>Settings</Button>
	{/snippet}
</PageHeader>

<div class="mb-5 grid gap-3 sm:grid-cols-3">
	<Stat label="Monitored devices" value={stateCounts?.devices ?? 0} icon={Network} href={withClient('/network')} />
	<Stat label="Down" value={stateCounts?.down ?? 0} tone="danger" icon={BellRing} href={withClient('/network?state=down')} />
	<Stat label="Unmanaged on the network" value={stateCounts?.unmanaged ?? 0} tone="warning" icon={ShieldQuestion} href={withClient('/network?tab=discovered')} />
</div>

<Tabs
	label="Network"
	class="mb-3"
	value={tab}
	onchange={(v) => { selected = new Set(); setParams({ tab: v === 'devices' ? null : v, state: null, found: null, kind: null }); }}
	items={[
		{ value: 'devices', label: 'Devices', count: stateCounts ? num(stateCounts.devices) : undefined },
		{ value: 'discovered', label: 'Discovered', count: stateCounts ? num(stateCounts.unmanaged) : undefined, title: 'Unmanaged hosts seen in the latest scans' }
	]}
/>

{#if tab === 'devices'}
	{#if devices.error && !devices.data}
		<div class="card"><ErrorState error={devices.error} onretry={() => devices.reload()} /></div>
	{:else}
		{#snippet nameCell(d: NetDevice)}
			<a class="hover:text-accent font-medium whitespace-nowrap" href="/network/devices/{d.id}">{d.name}</a>
			<div class="text-muted mt-0.5 max-w-64 truncate text-xs">{d.sys_descr ?? d.host}</div>
			<div class="mt-1 sm:hidden"><Badge tone={d.enabled ? stateTone[d.state] : 'neutral'}>{d.enabled ? stateLabel[d.state] : 'Paused'}</Badge></div>
		{/snippet}
		{#snippet stateCell(d: NetDevice)}
			<Badge tone={d.enabled ? stateTone[d.state] : 'neutral'}>{d.enabled ? stateLabel[d.state] : 'Paused'}</Badge>
			{#if d.state === 'down' && d.enabled}<div class="text-muted mt-0.5 text-xs whitespace-nowrap" title={datetime(d.state_since)}>{ago(d.state_since)}</div>{/if}
		{/snippet}
		{#snippet kindCell(d: NetDevice)}<span class="whitespace-nowrap">{kindLabel(d.kind)}</span>{/snippet}
		{#snippet hostCell(d: NetDevice)}<span class="font-mono text-[13px]">{d.host}</span>{/snippet}
		{#snippet siteCell(d: NetDevice)}<span class="text-muted whitespace-nowrap">{scoped ? d.site_name : `${d.client_name} › ${d.site_name}`}</span>{/snippet}
		{#snippet cpuCell(d: NetDevice)}{#if d.cpu_percent != null}<UsageBar bar={false} value={d.cpu_percent} />{:else}<span class="text-muted" aria-label="no data">–</span>{/if}{/snippet}
		{#snippet portsCell(d: NetDevice)}{#if d.interfaces}<span class="tabular whitespace-nowrap">{d.interfaces_up}/{d.interfaces} up</span>{:else}<span class="text-muted" aria-label="no data">–</span>{/if}{/snippet}
		{#snippet uptimeCell(d: NetDevice)}{#if d.uptime_secs != null}<span class="text-muted whitespace-nowrap">{duration(d.uptime_secs)}</span>{:else}<span class="text-muted">–</span>{/if}{/snippet}
		{#snippet alertsCell(d: NetDevice)}{#if d.open_alerts}<a href="/alerts?client={d.client_id}"><Badge tone="danger">{d.open_alerts} open</Badge></a>{:else}<span class="text-muted">–</span>{/if}{/snippet}
		{#snippet polledCell(d: NetDevice)}<span class="text-muted whitespace-nowrap" title={datetime(d.last_poll_at)}>{d.last_poll_at ? ago(d.last_poll_at) : 'never'}</span>{/snippet}

		<DataTable
			id="net-devices"
			caption="Monitored network devices"
			activeFilters={[param('site'), param('state'), param('kind')].filter(Boolean).length}
			rows={devRows}
			key={(d) => d.id}
			loading={devices.loading && !devices.data}
			{sort}
			rowHref={(d) => `/network/devices/${d.id}`}
			columns={[
				{ id: 'name', label: 'Device', sort: 'name', cell: nameCell, hideable: false },
				{ id: 'state', label: 'State', sort: 'state', cell: stateCell, from: 'sm' },
				{ id: 'kind', label: 'Kind', sort: 'kind', cell: kindCell, from: 'md' },
				{ id: 'host', label: 'Address', sort: 'host', cell: hostCell, from: 'lg' },
				{ id: 'site', label: scoped ? 'Site' : 'Client / site', sort: 'site', cell: siteCell, from: 'lg' },
				{ id: 'cpu', label: 'CPU', sort: 'cpu', cell: cpuCell, align: 'right', from: 'xl' },
				{ id: 'ports', label: 'Ports', cell: portsCell, align: 'right', from: 'xl' },
				{ id: 'uptime', label: 'Uptime', sort: 'uptime', cell: uptimeCell, align: 'right', defaultHidden: true },
				{ id: 'alerts', label: 'Alerts', sort: 'alerts', cell: alertsCell, from: 'md' },
				{ id: 'polled', label: 'Last read', sort: 'polled', cell: polledCell, align: 'right', from: 'xl' }
			] satisfies Column<NetDevice>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="Name, address, description…" aria-label="Search devices" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
			{/snippet}
			{#snippet filters()}
				{#if sites.length > 1}
					<Select aria-label="Site" class="w-full sm:w-auto" value={param('site')} onchange={(e) => setParams({ site: e.currentTarget.value })} options={[{ value: '', label: 'All sites' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]} />
				{/if}
				<Select aria-label="State" class="w-full sm:w-auto" value={param('state')} onchange={(e) => setParams({ state: e.currentTarget.value })} options={[{ value: '', label: 'Any state' }, { value: 'up', label: 'Up' }, { value: 'down', label: 'Down' }, { value: 'unknown', label: 'Not read yet' }]} />
				<Select aria-label="Kind" class="w-full sm:w-auto" value={param('kind')} onchange={(e) => setParams({ kind: e.currentTarget.value })} options={[{ value: '', label: 'Any kind' }, ...kindOptions]} />
			{/snippet}
			{#snippet empty()}
				{#if param('q') || param('site') || param('state') || param('kind')}
					<EmptyState title="No devices match" description="Try other filters.">
						{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, site: null, state: null, kind: null }); }}>Clear filters</Button>{/snippet}
					</EmptyState>
				{:else}
					<EmptyState icon={Network} title="No network devices yet" description="Choose a designated agent for a site and scan it, then monitor what's found. Or add a device by its address.">
						{#snippet action()}
							<div class="flex flex-wrap justify-center gap-2">
								<Button size="sm" variant="primary" icon={Settings} href={withClient('/network/settings')}>Set up discovery</Button>
								{#if can('technician')}<Button size="sm" icon={Plus} onclick={() => (adding = true)}>Add device</Button>{/if}
							</div>
						{/snippet}
					</EmptyState>
				{/if}
			{/snippet}
		</DataTable>
	{/if}
{:else if found.error && !found.data}
	<div class="card"><ErrorState error={found.error} onretry={() => found.reload()} /></div>
{:else}
	{#snippet fNameCell(d: Discovered)}
		<span class="font-medium whitespace-nowrap">{d.name}</span>
		<div class="text-muted mt-0.5 truncate text-xs">{d.sys_descr ?? d.vendor ?? d.mac ?? ''}</div>
	{/snippet}
	{#snippet fIpCell(d: Discovered)}<span class="font-mono text-[13px]">{d.ip}</span>{#if d.mac}<div class="text-muted font-mono text-xs">{d.mac}</div>{/if}{/snippet}
	{#snippet fKindCell(d: Discovered)}
		{#if can('technician')}
			<Select aria-label="Kind of {d.name}" class="w-48" value={d.kind} onchange={(e) => setKind(d, e.currentTarget.value)} options={kindOptions} />
		{:else}{kindLabel(d.kind)}{/if}
	{/snippet}
	{#snippet fVendorCell(d: Discovered)}<span class="text-muted">{d.vendor ?? '–'}</span>{/snippet}
	{#snippet fPortsCell(d: Discovered)}<span class="text-muted text-xs">{d.open_ports.length ? d.open_ports.slice(0, 5).map(portLabel).join(', ') + (d.open_ports.length > 5 ? ` +${d.open_ports.length - 5}` : '') : '–'}</span>{/snippet}
	{#snippet fSiteCell(d: Discovered)}<span class="text-muted whitespace-nowrap">{scoped ? d.site_name : `${d.client_name} › ${d.site_name}`}</span>{/snippet}
	{#snippet fStateCell(d: Discovered)}
		<Badge tone={discoveredTone[d.state]}>{discoveredLabel[d.state]}</Badge>
		{#if !d.online}<div class="text-muted mt-0.5 text-xs">offline</div>{/if}
		{#if d.state === 'managed' && d.agent_id}<a class="text-muted hover:text-fg block text-xs" href="/agents/{d.agent_id}">{d.agent_hostname}</a>{/if}
		{#if d.state === 'monitored' && d.net_device_id}<a class="text-muted hover:text-fg block text-xs" href="/network/devices/{d.net_device_id}">Open device</a>{/if}
		{#if d.state === 'known' && d.note}<div class="text-muted max-w-48 truncate text-xs" title={d.note}>{d.note}</div>{/if}
	{/snippet}
	{#snippet fSeenCell(d: Discovered)}<span class="text-muted whitespace-nowrap" title="First seen {datetime(d.first_seen_at)}">{ago(d.last_seen_at)}</span>{/snippet}
	{#snippet fActions(d: Discovered)}
		{#if can('technician') && ['unmanaged', 'known', 'ignored'].includes(d.state)}
			<div class="flex items-center justify-end gap-1.5">
				<Button size="xs" icon={Radar} onclick={() => (monitoring = d)}>Monitor</Button>
				<Menu
					label="More actions for {d.name}"
					items={[
						...(['windows', 'linux', 'server', 'nas', 'other'].includes(d.kind) ? [{ label: 'Deploy agent…', icon: Monitor, onSelect: () => deploy(d) }] : []),
						...(d.state === 'unmanaged' ? [{ label: 'Mark as known…', icon: Tag, onSelect: () => { noting = d; note = d.note; } }, { label: 'Ignore', icon: EyeOff, onSelect: () => mark([d.id], 'ignored') }] : []),
						...(d.state !== 'unmanaged' ? [{ label: 'Back to the unmanaged list', icon: Eye, onSelect: () => mark([d.id], 'unmanaged') }] : [])
					]}
				/>
			</div>
		{/if}
	{/snippet}

	<DataTable
		id="net-discovered"
		caption="Hosts found by network discovery"
		activeFilters={[param('site'), param('found')].filter(Boolean).length}
		rows={foundRows}
		key={(d) => d.id}
		loading={found.loading && !found.data}
		{sort}
		bind:selected
		columns={[
			{ id: 'name', label: 'Host', sort: 'name', cell: fNameCell, hideable: false },
			{ id: 'ip', label: 'Address', sort: 'host', cell: fIpCell },
			{ id: 'kind', label: 'Kind', sort: 'kind', cell: fKindCell, from: 'md' },
			{ id: 'vendor', label: 'Vendor', sort: 'vendor', cell: fVendorCell, from: 'xl' },
			{ id: 'ports', label: 'Open ports', cell: fPortsCell, from: 'xl', defaultHidden: true },
			{ id: 'site', label: scoped ? 'Site' : 'Client / site', sort: 'site', cell: fSiteCell, from: 'lg' },
			{ id: 'state', label: 'State', sort: 'state', cell: fStateCell, from: 'sm' },
			{ id: 'seen', label: 'Last seen', sort: 'seen', cell: fSeenCell, align: 'right', from: 'lg' },
			{ id: 'actions', label: '', cell: fActions, align: 'right', hideable: false }
		] satisfies Column<Discovered>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Name, address, MAC, vendor…" aria-label="Search discovered hosts" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			{#if sites.length > 1}
				<Select aria-label="Site" class="w-full sm:w-auto" value={param('site')} onchange={(e) => setParams({ site: e.currentTarget.value })} options={[{ value: '', label: 'All sites' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]} />
			{/if}
			<Select
				aria-label="Show"
				class="w-full sm:w-auto"
				value={dstate}
				onchange={(e) => setParams({ found: e.currentTarget.value === 'unmanaged' ? null : e.currentTarget.value })}
				options={[
					{ value: 'unmanaged', label: 'Unmanaged' }, { value: 'managed', label: 'Managed (has an agent)' }, { value: 'monitored', label: 'Monitored over SNMP' },
					{ value: 'known', label: 'Known' }, { value: 'ignored', label: 'Ignored' }, { value: 'all', label: 'Everything' }
				]}
			/>
		{/snippet}
		{#snippet bulk(n)}
			{#if can('technician')}
				<Button size="sm" icon={Tag} onclick={() => mark([...selected], 'known')}>Mark as known</Button>
				<Button size="sm" icon={EyeOff} onclick={() => mark([...selected], 'ignored')}>Ignore {n === 1 ? 'it' : 'them'}</Button>
			{/if}
		{/snippet}
		{#snippet empty()}
			{#if param('q') || param('site') || param('found')}
				<EmptyState title="Nothing matches" description="Try other filters.">
					{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, site: null, found: null }); }}>Clear filters</Button>{/snippet}
				</EmptyState>
			{:else}
				<EmptyState icon={Radar} title="No unmanaged hosts" description="Everything seen in the latest scans has an agent, is monitored, or was marked. Scans run from each site's Network settings.">
					{#snippet action()}<Button size="sm" icon={Settings} href={withClient('/network/settings')}>Network settings</Button>{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</DataTable>
{/if}

{#if adding}
	<DeviceDialog siteId={param('site') || (scoped?.sites.length === 1 ? scoped.sites[0].id : '')} onclose={() => (adding = false)} ondone={() => ((adding = false), reloadAll())} />
{/if}
{#if monitoring}
	<MonitorDialog host={monitoring} onclose={() => (monitoring = null)} ondone={() => ((monitoring = null), reloadAll())} />
{/if}
{#if noting}
	<Modal title="Mark {noting.name} as known" description="Accepted without an agent (the label printer, a guest laptop). It leaves the unmanaged list." onclose={() => (noting = null)} size="sm">
		<label class="label" for="known-note">Note</label>
		<Textarea id="known-note" rows={3} maxlength={500} bind:value={note} placeholder="Reception label printer" />
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (noting = null)}>Cancel</Button>
			<Button variant="primary" onclick={() => { const h = noting!; noting = null; mark([h.id], 'known', note); }}>Mark as known</Button>
		{/snippet}
	</Modal>
{/if}
{#if deploying}
	{@const h = deploying.host}
	<Modal title="Deploy an agent to {h.name}" description="{h.ip} · {kindLabel(h.kind)}" onclose={() => (deploying = null)}>
		{#if deploying.hint.ways.length}
			<p class="mb-3 text-sm">From its open ports, ways to install the agent:</p>
			<ul class="space-y-2 text-sm">
				{#each deploying.hint.ways as w (w.via)}
					<li class="border-border rounded-md border px-3 py-2"><span class="font-semibold uppercase">{w.via}</span> <span class="text-muted">port {w.port}</span><br />{w.text}</li>
				{/each}
			</ul>
		{:else if deploying.hint.manageable}
			<p class="text-sm">No remote-access port answered. Install the agent on the machine itself.</p>
		{:else}
			<p class="text-sm">This looks like a network appliance; it can't run an agent. Use <strong>Monitor</strong> to read it over SNMP.</p>
		{/if}
		<p class="text-muted mt-4 text-xs">Enrollment tokens are made from the site's <a class="link" href={withClient('/clients', h.client_id)}>Install agent</a> dialog; none is created here.</p>
		{#snippet footer()}<Button onclick={() => (deploying = null)}>Close</Button>{/snippet}
	</Modal>
{/if}
