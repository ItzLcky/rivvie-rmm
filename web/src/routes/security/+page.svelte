<script lang="ts">
	import { CloudDownload, Network, ScanSearch, Search, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, withClient } from '#lib/scope.svelte.js';
	import { ROOT_SET } from '#lib/policy/policy.js';
	import {
		actionNouns, databaseStale, riskSummary, foundByHelp, foundByLabels, productLabels, realtimeView, resourceLabel, riskLabels, severityLabels, severityTone, sourceLabels,
		stateHelp, stateLabels, states, threatStatusLabels, threatStatusTone, verdictLabels, verdictTone
	} from '#lib/security.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { DetectionSource, ProtectionState, SecurityAction, SecurityAgentRow, SecurityDetection, SecuritySummary } from '#lib/types.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import Status from '#lib/components/Status.svelte';
	import ProtectionBadge from '#lib/components/security/ProtectionBadge.svelte';
	import ReputationLists from '#lib/components/security/ReputationLists.svelte';
	import SecurityContent from '#lib/components/security/SecurityContent.svelte';
	import SignatureDatabases from '#lib/components/security/SignatureDatabases.svelte';
	import SecurityHunt from '#lib/components/security/SecurityHunt.svelte';
	import SecurityQuarantine from '#lib/components/security/SecurityQuarantine.svelte';
	import DiskEncryptionFleet from '#lib/components/security/DiskEncryptionFleet.svelte';
	import SecurityRules from '#lib/components/security/SecurityRules.svelte';
	import SecuritySettings from '#lib/components/security/SecuritySettings.svelte';

	const tab = $derived(param('tab', 'agents'));
	const scoped = $derived(currentClient());
	const STALE_MS = 72 * 3600 * 1000;

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});

	const summary = resource(() => api.get<SecuritySummary>(`/security/summary${qs({ client_id: clientId() })}`));
	liveReload(() => summary.reload(), (e) => e.type === 'security' || e.type === 'agent', { debounceMs: 2000, pollMs: 60000 });

	// --- Agents ---------------------------------------------------------------------------------
	const agentSort = sortState('state', 'asc');
	const stateFilter = $derived(param('state'));
	const os = $derived(param('os'));
	const agents = paged<SecurityAgentRow>(() =>
		tab === 'agents'
			? `/security/agents${qs({ client_id: clientId(), state: stateFilter, os, q: param('q'), sort: agentSort.key, dir: agentSort.dir })}`
			: '/security/agents?limit=1'
	);
	liveReload(() => tab === 'agents' && agents.reload(), (e) => e.type === 'security', { debounceMs: 1500 });
	let selected = $state(new Set<string>());

	async function startBulk(action: SecurityAction) {
		const ids = [...selected];
		await attempt(async () => {
			const r = await api.post<{ started: number; skipped: { hostname: string; reason: string }[] }>('/security/actions', { agent_ids: ids, action });
			const skipped = r.skipped.length ? ` Skipped ${plural(r.skipped.length, 'agent')}: ${r.skipped.slice(0, 3).map((s) => `${s.hostname} (${s.reason})`).join('; ')}${r.skipped.length > 3 ? '…' : ''}` : '';
			if (r.started) toast.success(`Started a ${actionNouns[action]} on ${plural(r.started, 'agent')}.${skipped}`);
			else toast.error(`Nothing started.${skipped}`);
		});
		selected = new Set();
		agents.reload();
	}

	// --- Detections -------------------------------------------------------------------------------
	const detSort = sortState('first_seen', 'desc');
	const view = $derived(param('view') === 'all' ? 'all' : 'active');
	const severity = $derived(param('severity'));
	const source = $derived(param('source'));
	const audit = $derived(param('audit') === 'true');
	const detections = paged<SecurityDetection>(() =>
		tab === 'detections'
			? `/security/detections${qs({ client_id: clientId(), view, severity, source, audit: audit || null, rule_id: param('rule_id'), sha256: param('sha256'), q: param('q'), sort: detSort.key, dir: detSort.dir })}`
			: '/security/detections?limit=1'
	);
	liveReload(() => tab === 'detections' && detections.reload(), (e) => e.type === 'security', { debounceMs: 1500 });

	const canRespond = $derived(allowed('security.respond'));
	const canManage = $derived(allowed('security.manage'));
	const sources: DetectionSource[] = ['product', 'file', 'behaviour'];

	const tile = (s: ProtectionState) => withClient(`/security${qs({ state: s })}`);
	const isStale = (iso: string | null) => !!iso && Date.now() - Date.parse(iso) > STALE_MS;
</script>

<svelte:head><title>Security</title></svelte:head>

<PageHeader title="Security" description={scoped ? `Protection on ${scoped.name}'s agents.` : 'The antivirus each machine already has (Microsoft Defender, ClamAV, XProtect), our own sensor, their findings, and the response to them.'}>
	{#snippet actions()}<Button icon={ShieldCheck} href="/policies/sets/{ROOT_SET}?section=alerts&item=new&kind=security">Alert on protection</Button>{/snippet}
</PageHeader>

{#if summary.data}
	{@const s = summary.data}
	{@const total = states.reduce((n, k) => n + (s.agents[k] ?? 0), 0)}
	<section aria-label="Protection" class="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
		<Stat label="Active threats" value={s.active_threats} tone="danger" href={withClient('/security?tab=detections')} />
		<Stat label={stateLabels.unprotected} value={s.agents.unprotected} tone="danger" href={tile('unprotected')} />
		<Stat label={stateLabels.at_risk} value={s.agents.at_risk} tone="warning" href={tile('at_risk')} />
		<Stat label="Not reporting" value={s.agents.unknown} href={tile('unknown')} />
		<Stat label={stateLabels.protected} value={s.agents.protected} of={total} href={tile('protected')} />
	</section>
{/if}

<Tabs
	label="Security sections"
	class="mb-3"
	value={tab}
	onchange={(v) => setParams({ tab: v === 'agents' ? null : v, state: null, view: null, severity: null, source: null, audit: null, rule_id: null, sha256: null, text: null, show: null, after: null, before: null, sort: null, dir: null }, { push: true })}
	items={[
		{ value: 'agents', label: 'Agents' },
		{ value: 'detections', label: 'Detections', count: summary.data?.active_threats ? num(summary.data.active_threats) : undefined },
		{ value: 'quarantine', label: 'Quarantine' },
		{ value: 'encryption', label: 'Disk encryption' },
		{ value: 'hunt', label: 'Hunt' },
		{ value: 'rules', label: 'Rules' },
		{ value: 'content', label: 'Content' },
		{ value: 'settings', label: 'Settings' }
	]}
/>

{#if tab === 'agents'}
	{#snippet agentCell(a: SecurityAgentRow)}
		<a class="hover:text-accent font-medium" href="/agents/{a.id}?tab=security">{a.hostname}</a>
		<div class="text-muted flex flex-wrap items-center gap-x-2 text-xs"><Status online={a.online} /><span class="truncate">{scoped ? a.site_name : `${a.client_name} › ${a.site_name}`}</span></div>
	{/snippet}
	{#snippet stateCell(a: SecurityAgentRow)}
		<span class="inline-flex flex-wrap items-center gap-1">
			<ProtectionBadge state={a.state} title={a.security_error ?? (a.risks?.length ? a.risks.map((r) => riskLabels[r]).join('; ') : stateHelp[a.state])} />
			{#if a.isolated}<Badge tone="danger" icon={Network} title="Only the RMM server, DNS and DHCP are reachable">Isolated</Badge>{/if}
		</span>
		{#if a.state === 'at_risk' && a.risks?.length}<div class="text-muted text-xs">{riskSummary(a.risks)}</div>{/if}
		{#if a.running_action}<div class="text-info text-xs">{actionNouns[a.running_action]} running</div>{/if}
	{/snippet}
	{#snippet productsCell(a: SecurityAgentRow)}
		{#each a.products as p (p.kind + p.name)}
			<div class="truncate">
				{p.name}{#if p.enabled === false}<span class="text-danger">{' · off'}</span>{:else if p.kind === 'rmm' && a.os_family !== 'linux'}<span class="text-muted">{' · scans after start'}</span>{:else if p.realtime === false}<span class="text-warning">{' · no real-time'}</span>{/if}
			</div>
		{:else}
			<span class="text-muted">{a.security_at ? 'None found' : '–'}</span>
		{/each}
	{/snippet}
	{#snippet sigCell(a: SecurityAgentRow)}
		{#if a.signatures_updated_at}
			<span class="whitespace-nowrap" title={datetime(a.signatures_updated_at)}>{ago(a.signatures_updated_at)}</span>
			{#if isStale(a.signatures_updated_at)}<Badge tone="warning">Out of date</Badge>{/if}
		{:else}<span class="text-muted">–</span>{/if}
	{/snippet}
	{#snippet sensorCell(a: SecurityAgentRow)}
		{#if !a.sensor}
			<span class="text-muted">–</span>
		{:else if !a.sensor.enabled}
			<span class="text-muted">Off</span>
		{:else if !a.sensor.running}
			<Badge tone="danger" title={a.sensor.error ?? undefined}>Not running</Badge>
		{:else if a.sensor.restarts >= 3}
			<Badge tone="warning">Keeps restarting</Badge>
		{:else}
			<span class="text-muted">Running</span>
		{/if}
		{#if a.sensor?.enabled}
			{@const v = a.sensor.running ? realtimeView(a.sensor.health?.realtime, a.os_family, true, a.prevention) : null}
			{#if v}
				<div class="text-xs">{#if v.fault}<Badge tone="warning" title={v.detail ?? undefined}>Real-time {v.label.toLowerCase()}</Badge>{:else}<span class="text-muted" title={v.detail ?? undefined}>Real-time {v.label.charAt(0).toLowerCase() + v.label.slice(1)}</span>{/if}</div>
			{/if}
			{#if a.database_version}
				<div class="flex flex-wrap items-center gap-1 text-xs">
					<span class="text-muted font-mono">{a.database_version}</span>
					{#if a.database_built_at}<span class="text-muted" title={datetime(a.database_built_at)}>{ago(a.database_built_at)}</span>{/if}
					{#if databaseStale(a.database_built_at, a.database_max_age_hours)}<Badge tone="warning" title="Older than the policy's {a.database_max_age_hours} hours">Out of date</Badge>{/if}
				</div>
			{:else if a.content_version ?? a.sensor.content_version}
				<div class="text-muted font-mono text-xs" title="Content version; no signature database yet">{a.content_version ?? a.sensor.content_version}</div>
			{/if}
		{/if}
	{/snippet}
	{#snippet scanCell(a: SecurityAgentRow)}
		{#if a.last_scan_at}<span class="whitespace-nowrap" title={datetime(a.last_scan_at)}>{ago(a.last_scan_at)}</span>{:else}<span class="text-muted">–</span>{/if}
	{/snippet}
	{#snippet threatsCell(a: SecurityAgentRow)}
		{#if a.active_threats}<a class="text-danger font-semibold tabular" href="/agents/{a.id}?tab=security">{num(a.active_threats)}</a>{:else}<span class="text-muted tabular">0</span>{/if}
	{/snippet}

	{#if agents.error && !agents.data}
		<div class="card"><ErrorState error={agents.error} onretry={() => agents.reload()} /></div>
	{:else}
		<DataTable
			id="security-agents"
			caption="Agents by protection"
			activeFilters={(stateFilter ? 1 : 0) + (os ? 1 : 0)}
			rows={agents.rows}
			key={(a) => a.id}
			loading={agents.loading}
			busy={agents.busy}
			sort={agentSort}
			bind:selected={() => (canRespond ? selected : undefined), (v) => (selected = v ?? new Set())}
			rowHref={(a) => `/agents/${a.id}?tab=security`}
			columns={[
				{ id: 'agent', label: 'Agent', sort: 'hostname', cell: agentCell, hideable: false },
				{ id: 'state', label: 'Protection', sort: 'state', cell: stateCell },
				{ id: 'products', label: 'Antivirus', cell: productsCell, from: 'md' },
				{ id: 'sensor', label: 'Sensor', cell: sensorCell, from: 'lg' },
				{ id: 'signatures', label: 'Signatures', sort: 'signatures', cell: sigCell, from: 'sm' },
				{ id: 'scan', label: 'Last scan', sort: 'last_scan', cell: scanCell, from: 'lg' },
				{ id: 'threats', label: 'Threats', sort: 'threats', cell: threatsCell, align: 'right', from: 'sm' }
			] satisfies Column<SecurityAgentRow>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="Hostname…" aria-label="Search agents" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
			{/snippet}
			{#snippet filters()}
				<Select aria-label="Protection" class="w-full sm:w-auto" value={stateFilter} onchange={(e) => setParams({ state: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any protection' }, ...states.map((s) => ({ value: s, label: stateLabels[s] }))]} />
				<Select aria-label="Operating system" class="w-full sm:w-auto" value={os} onchange={(e) => setParams({ os: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any OS' }, { value: 'windows', label: 'Windows' }, { value: 'linux', label: 'Linux' }, { value: 'macos', label: 'macOS' }]} />
			{/snippet}
			{#snippet bulk(n)}
				<Button size="sm" icon={ScanSearch} onclick={() => startBulk('quick_scan')}>Quick scan {n}</Button>
				<Button size="sm" icon={CloudDownload} onclick={() => startBulk('update_signatures')}>Update signatures on {n}</Button>
			{/snippet}
			{#snippet empty()}
				<EmptyState compact title={stateFilter || os || param('q') ? 'No agents match' : 'No agents yet'} />
			{/snippet}
			{#snippet footer()}
				{#if agents.data}
					<Pagination shown={agents.rows.length} total={agents.data.total} exact={agents.data.total_exact} hasPrev={!!agents.data.prev} hasNext={!!agents.data.next} pageSize={agents.pageSize} onprev={agents.prev} onnext={agents.next} onfirst={agents.first} onpagesize={agents.setPageSize} />
				{/if}
			{/snippet}
		</DataTable>
	{/if}
{:else if tab === 'detections'}
	{#snippet threatCell(d: SecurityDetection)}
		<a class="hover:text-accent font-medium break-words" href="/security/detections/{d.id}">{d.name}</a>
		{#if d.audit}<Badge class="ml-1" title="Recorded by a rule in audit mode: no alert, no action">Audit</Badge>{/if}
		{#if d.rule_id || d.mitre.length}<div class="text-muted font-mono text-xs">{[d.rule_id, ...d.mitre].filter(Boolean).join(' · ')}</div>{/if}
		{#if d.resources[0]}<div class="text-muted max-w-md truncate font-mono text-xs" title={d.resources.map(resourceLabel).join('\n')}>{resourceLabel(d.resources[0])}{d.resources.length > 1 ? ` +${d.resources.length - 1}` : ''}</div>{/if}
	{/snippet}
	{#snippet detAgentCell(d: SecurityDetection)}
		<a class="hover:text-accent font-medium" href="/agents/{d.agent_id}?tab=security">{d.hostname}</a>
		<div class="text-muted truncate text-xs">{d.client_name} › {d.site_name}</div>
	{/snippet}
	{#snippet sevCell(d: SecurityDetection)}<Badge tone={severityTone[d.severity]}>{severityLabels[d.severity]}</Badge>{/snippet}
	{#snippet statusCell(d: SecurityDetection)}
		<span class="inline-flex flex-wrap gap-1">
			<Badge tone={!d.resolved_at && d.status === 'active' && !d.audit ? 'danger' : d.audit ? 'neutral' : threatStatusTone[d.status]}>{d.audit && d.status === 'active' ? 'Recorded' : threatStatusLabels[d.status]}</Badge>
			{#if d.denied}<Badge title="Refused before it ran">Denied</Badge>{/if}
			{#if d.verdict}<Badge tone={verdictTone[d.verdict]}>{verdictLabels[d.verdict]}</Badge>{/if}
		</span>
		<div class="text-muted text-xs" title={d.found_by ? foundByHelp[d.found_by] : undefined}>{d.product === 'rmm' ? `${productLabels.rmm} · ${d.found_by ? foundByLabels[d.found_by].toLowerCase() : sourceLabels[d.source].toLowerCase()}` : productLabels[d.product]}</div>
	{/snippet}
	{#snippet seenCell(d: SecurityDetection)}<span class="whitespace-nowrap" title={datetime(d.detected_at ?? d.first_seen_at)}>{ago(d.detected_at ?? d.first_seen_at)}</span>{/snippet}

	{#if detections.error && !detections.data}
		<div class="card"><ErrorState error={detections.error} onretry={() => detections.reload()} /></div>
	{:else}
		<DataTable
			id="security-detections"
			caption="Detections"
			activeFilters={(severity ? 1 : 0) + (source ? 1 : 0) + (audit ? 1 : 0)}
			rows={detections.rows}
			key={(d) => d.id}
			loading={detections.loading}
			busy={detections.busy}
			sort={detSort}
			rowHref={(d) => `/security/detections/${d.id}`}
			columns={[
				{ id: 'threat', label: 'Threat', sort: 'name', cell: threatCell, hideable: false },
				{ id: 'agent', label: 'Agent', sort: 'hostname', cell: detAgentCell, from: 'sm' },
				{ id: 'severity', label: 'Severity', sort: 'severity', cell: sevCell, from: 'md' },
				{ id: 'status', label: 'Status', cell: statusCell },
				{ id: 'seen', label: 'Detected', sort: 'first_seen', cell: seenCell, from: 'sm' }
			] satisfies Column<SecurityDetection>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="Threat, file or agent…" aria-label="Search detections" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
				<Segmented label="Show" value={view} onchange={(v) => setParams({ view: v === 'active' ? null : v, after: null, before: null })} options={[{ value: 'active', label: 'Active' }, { value: 'all', label: 'All' }]} />
			{/snippet}
			{#snippet filters()}
				<Select aria-label="Severity" class="w-full sm:w-auto" value={severity} onchange={(e) => setParams({ severity: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any severity' }, ...(['severe', 'high', 'moderate', 'low', 'unknown'] as const).map((s) => ({ value: s, label: severityLabels[s] }))]} />
				<Select aria-label="Found by" class="w-full sm:w-auto" value={source} onchange={(e) => setParams({ source: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any source' }, ...sources.map((s) => ({ value: s, label: s === 'product' ? 'Antivirus' : `Sensor: ${sourceLabels[s].toLowerCase()}` }))]} />
				<Switch checked={audit} onchange={(on) => setParams({ audit: on ? 'true' : null, after: null, before: null })}>Include audit hits</Switch>
			{/snippet}
			{#snippet empty()}
				{#if view === 'active' && !severity && !source && !param('q')}
					<EmptyState icon={ShieldCheck} title="No active threats" description="Everything the antivirus found has been quarantined or removed. See All for the history." />
				{:else}
					<EmptyState compact title="No detections match" />
				{/if}
			{/snippet}
			{#snippet footer()}
				{#if detections.data}
					<Pagination shown={detections.rows.length} total={detections.data.total} exact={detections.data.total_exact} hasPrev={!!detections.data.prev} hasNext={!!detections.data.next} pageSize={detections.pageSize} onprev={detections.prev} onnext={detections.next} onfirst={detections.first} onpagesize={detections.setPageSize} />
				{/if}
			{/snippet}
		</DataTable>
	{/if}
{:else if tab === 'quarantine'}
	<SecurityQuarantine />
{:else if tab === 'encryption'}
	<DiskEncryptionFleet />
{:else if tab === 'hunt'}
	<SecurityHunt />
{:else if tab === 'rules'}
	<SecurityRules {canManage} />
{:else if tab === 'content'}
	<SecurityContent {canManage} />
	<div class="mt-6"><SignatureDatabases {canManage} /></div>
	<div class="mt-6"><ReputationLists {canManage} /></div>
{:else if tab === 'settings'}
	<SecuritySettings {canManage} />
{/if}
