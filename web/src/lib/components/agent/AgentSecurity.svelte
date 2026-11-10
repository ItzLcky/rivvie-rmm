<script lang="ts">
	import { ChevronDown, CloudDownload, FileSearch, FileX2, Network, PackageOpen, RefreshCw, ScanSearch, Search, ShieldCheck, Skull, Unplug } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import {
		actionLabels, actionNouns, actionStatusLabels, actionStatusTone, productLabels, resourceLabel, severityLabels, severityTone,
		sourceLabels, stateHelp, threatStatusLabels, threatStatusTone, verdictLabels, verdictTone
	} from '#lib/security.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { AgentSecurity, SecurityAction, SecurityDetection, SecurityProduct } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import ActionHistory from '#lib/components/security/ActionHistory.svelte';
	import ProtectionBadge from '#lib/components/security/ProtectionBadge.svelte';
	import QuarantineList from '#lib/components/security/QuarantineList.svelte';
	import RespondDialog, { type RespondKind } from '#lib/components/security/RespondDialog.svelte';
	import SensorCard from '#lib/components/security/SensorCard.svelte';
	import TelemetryPanel from '#lib/components/security/TelemetryPanel.svelte';

	let { agentId, hostname }: { agentId: string; hostname: string } = $props();
	const res = resource(() => api.get<AgentSecurity>(`/agents/${agentId}/security`));
	liveReload(() => res.reload(), (e) => e.type === 'security' && e.agent_id === agentId, { debounceMs: 400, pollMs: 60000 });

	/** The user's pick; until then, active threats if there are any, else the history. */
	let picked = $state<'active' | 'all' | null>(null);
	let q = $state('');
	let starting = $state<string | null>(null);
	const STALE_MS = 72 * 3600 * 1000;

	const running = $derived((res.data?.actions ?? []).find((a) => a.status === 'sent' || a.status === 'running'));
	const isActive = (d: SecurityDetection) => !d.resolved_at && d.status === 'active' && !d.audit;
	const detections: SecurityDetection[] = $derived.by(() => {
		const f = q.trim().toLowerCase();
		return (res.data?.detections ?? []).filter(
			(d) => (show === 'all' || isActive(d)) && (!f || `${d.name} ${d.resources.join(' ')}`.toLowerCase().includes(f))
		);
	});
	const activeCount = $derived((res.data?.detections ?? []).filter(isActive).length);
	const show = $derived(picked ?? (activeCount ? 'active' : 'all'));

	function stale(p: SecurityProduct): boolean {
		if (p.signatures_updated_at) return Date.now() - Date.parse(p.signatures_updated_at) > STALE_MS;
		return p.signatures_current === false;
	}

	async function run(p: SecurityProduct, action: SecurityAction) {
		if (action === 'full_scan') {
			const ok = await confirmAction({
				title: `Full scan of ${hostname}?`,
				message: `${p.name} reads every file on the machine. It can take hours and slows the machine down while it runs.`,
				confirmLabel: 'Start full scan'
			});
			if (!ok) return;
		}
		starting = `${p.kind}:${action}`;
		await attempt(
			() => api.post(`/agents/${agentId}/security/actions`, { action, product: p.kind }),
			`${actionLabels[action]} started. The result shows here when ${p.name} finishes.`
		);
		starting = null;
		res.reload();
	}
	async function refresh() {
		await attempt(() => api.post(`/agents/${agentId}/security/refresh`), 'Asked the agent for its current state.');
	}
	const icons = { quick_scan: ScanSearch, full_scan: ScanSearch, update_signatures: CloudDownload };

	const canRespond = $derived(allowed('security.respond'));
	let responding = $state<RespondKind | null>(null);
	const respondItems = [
		{ label: 'Collect triage package…', icon: PackageOpen, onSelect: () => (responding = 'collect_triage') },
		{ label: 'Scan a path…', icon: FileSearch, onSelect: () => (responding = 'scan_path') },
		{ separator: true as const },
		{ label: 'Quarantine a file…', icon: FileX2, onSelect: () => (responding = 'quarantine_file') },
		{ label: 'Kill a process…', icon: Skull, onSelect: () => (responding = 'kill_process') }
	];
</script>

{#snippet onOff(v: boolean | null, good = 'On', bad = 'Off')}
	{#if v === null}<span class="text-muted">–</span>{:else if v}{good}{:else}<Badge tone="danger">{bad}</Badge>{/if}
{/snippet}

{#snippet threatCell(d: SecurityDetection)}
	<a class="hover:text-accent font-medium break-words" href="/security/detections/{d.id}">{d.name}</a>
	{#if d.audit}<Badge class="ml-1" title="Recorded by a rule in audit mode: no alert, no action">Audit</Badge>{/if}
	{#if d.rule_id || d.mitre.length}<div class="text-muted font-mono text-xs">{[d.rule_id, ...d.mitre].filter(Boolean).join(' · ')}</div>{/if}
	{#each d.resources.slice(0, 2) as r (r)}<div class="text-muted font-mono text-xs break-all">{resourceLabel(r)}</div>{/each}
	{#if d.resources.length > 2}<div class="text-muted text-xs">+{d.resources.length - 2} more</div>{/if}
{/snippet}
{#snippet sevCell(d: SecurityDetection)}<Badge tone={severityTone[d.severity]}>{severityLabels[d.severity]}</Badge>{/snippet}
{#snippet statusCell(d: SecurityDetection)}
	<Badge tone={isActive(d) ? 'danger' : d.audit ? 'neutral' : threatStatusTone[d.status]}>{d.audit && d.status === 'active' ? 'Recorded' : threatStatusLabels[d.status]}</Badge>
	{#if d.verdict}<div class="mt-0.5"><Badge tone={verdictTone[d.verdict]}>{verdictLabels[d.verdict]}</Badge></div>{/if}
	{#if d.resolved_at && d.status === 'active'}<div class="text-muted text-xs">no longer reported</div>{/if}
{/snippet}
{#snippet whenCell(d: SecurityDetection)}
	<span class="whitespace-nowrap" title={datetime(d.detected_at ?? d.first_seen_at)}>{ago(d.detected_at ?? d.first_seen_at)}</span>
	{#if d.username || d.process}<div class="text-muted max-w-48 truncate text-xs" title={[d.username, d.process].filter(Boolean).join(' · ')}>{[d.username, d.process].filter(Boolean).join(' · ')}</div>{/if}
{/snippet}
{#snippet productCell(d: SecurityDetection)}
	<span class="text-muted">{productLabels[d.product]}</span>
	{#if d.product === 'rmm'}<div class="text-muted text-xs">{sourceLabels[d.source]}</div>{/if}
{/snippet}

<Async {res}>
	{#snippet skeleton()}
		<div class="grid gap-4 lg:grid-cols-2"><div class="card p-4"><Skeleton lines={6} /></div><div class="card p-4"><Skeleton lines={6} /></div></div>
	{/snippet}
	{#snippet children(s)}
		{@const products = s.products.filter((p) => p.kind !== 'rmm')}
		{@const sensorProduct = s.products.find((p) => p.kind === 'rmm')}
		{#if !s.supported}
			<div class="card">
				<EmptyState icon={ShieldCheck} title="This agent doesn’t report its protection yet" description="Its version predates endpoint protection. Update the agent and it starts reporting its antivirus." />
			</div>
		{:else}
			<div class="mb-4 flex flex-wrap items-center gap-x-3 gap-y-2">
				<ProtectionBadge state={s.state} />
				<span class="text-muted text-sm">{stateHelp[s.state]}</span>
				<span class="text-muted text-xs">{s.reported_at ? `Reported ${ago(s.reported_at)}` : 'Waiting for the first report'}</span>
				<div class="ml-auto flex flex-wrap gap-1.5">
					<Button size="sm" icon={RefreshCw} disabled={!s.online} title={s.online ? undefined : 'The agent is offline'} onclick={refresh}>Refresh</Button>
					{#if canRespond && s.sensor_supported}
						{#if !s.isolated}
							<Button size="sm" icon={Unplug} disabled={!s.online} title={s.online ? undefined : 'The agent is offline'} onclick={() => (responding = 'isolate')}>Isolate network…</Button>
						{/if}
						{#if s.online}
							<Menu label="Respond" items={respondItems}>
								{#snippet trigger(props)}<Button {...props} size="sm" variant="primary" iconRight={ChevronDown}>Respond</Button>{/snippet}
							</Menu>
						{:else}
							<Button size="sm" variant="primary" iconRight={ChevronDown} disabled title="The agent is offline">Respond</Button>
						{/if}
					{/if}
				</div>
			</div>
			{#if s.isolated}
				<div class="border-danger/40 bg-danger-soft mb-4 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border px-3 py-2.5 text-sm" role="status">
					<Network class="text-danger size-4 shrink-0" aria-hidden="true" />
					<div class="min-w-0 flex-1">
						<span class="text-danger font-semibold">Isolated from the network.</span>
						<span class="text-fg">Only this RMM server, DNS and DHCP are reachable. Scripts, the terminal and remote desktop still work.</span>
					</div>
					{#if canRespond}
						<Button size="sm" disabled={!s.online} title={s.online ? undefined : 'The agent is offline; it releases when told to'} onclick={() => (responding = 'release')}>Release</Button>
					{/if}
				</div>
			{/if}
			{#if s.error}<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-sm" role="status">The agent couldn’t read everything: {s.error}</p>{/if}
			{#if running}
				<p class="border-info/40 bg-info-soft text-info mb-4 rounded-md border px-3 py-2 text-sm" role="status">
					A {actionNouns[running.action]} is {running.status === 'sent' ? 'starting' : 'running'}{running.product === 'rmm' && !['quick_scan', 'full_scan', 'update_signatures'].includes(running.action) ? '' : ` with ${productLabels[running.product]}`}{running.started_at ? `, since ${ago(running.started_at)}` : ''}.
				</p>
			{/if}

			{#if products.length === 0 && !s.sensor_supported}
				<div class="card mb-4">
					<EmptyState
						icon={ShieldCheck}
						title={s.reported_at ? 'No antivirus found' : 'No report yet'}
						description={s.reported_at ? 'The agent found no supported antivirus: Microsoft Defender or another product registered with Windows Security Center, ClamAV on Linux, XProtect on macOS.' : 'The agent reports its antivirus shortly after connecting.'}
					/>
				</div>
			{:else}
				<div class="mb-4 grid gap-4 lg:grid-cols-2">
					{#if s.sensor_supported}
						<SensorCard sensor={s.sensor} policy={s.policy} product={sensorProduct} reportedAt={s.sensor_at}>
							{#snippet actions()}
								{#if canRespond && sensorProduct?.actions.length}
									<div class="flex flex-wrap gap-1.5">
										{#each sensorProduct.actions as a (a)}
											<Button
												size="sm"
												icon={icons[a]}
												loading={starting === `rmm:${a}`}
												disabled={!s.online || !!running || starting !== null}
												title={!s.online ? 'The agent is offline' : running ? `A ${actionNouns[running.action]} is already running` : undefined}
												onclick={() => run(sensorProduct, a)}>{actionLabels[a]}</Button
											>
										{/each}
									</div>
								{/if}
							{/snippet}
						</SensorCard>
					{/if}
					{#each products as p (p.kind + p.name)}
						<section class="card p-4" aria-label={p.name}>
							<div class="mb-3 flex flex-wrap items-start justify-between gap-2">
								<div class="min-w-0">
									<h2 class="text-sm font-semibold">{p.name}</h2>
									{#if p.version}<div class="text-muted font-mono text-xs">v{p.version}</div>{/if}
								</div>
								{#if canRespond && p.actions.length}
									<div class="flex flex-wrap gap-1.5">
										{#each p.actions as a (a)}
											<Button
												size="sm"
												icon={icons[a]}
												loading={starting === `${p.kind}:${a}`}
												disabled={!s.online || !!running || starting !== null}
												title={!s.online ? 'The agent is offline' : running ? `A ${actionNouns[running.action]} is already running` : undefined}
												onclick={() => run(p, a)}>{actionLabels[a]}</Button
											>
										{/each}
									</div>
								{/if}
							</div>
							<dl class="dl">
								<dt>Antivirus</dt><dd>{@render onOff(p.enabled)}</dd>
								<dt>Real-time</dt><dd>{@render onOff(p.realtime)}</dd>
								<dt>Signatures</dt>
								<dd>
									{#if p.signatures_updated_at}
										<span title={datetime(p.signatures_updated_at)}>{ago(p.signatures_updated_at)}</span>
									{:else if p.signatures_current !== null}
										{p.signatures_current ? 'Up to date' : ''}
									{:else}<span class="text-muted">–</span>{/if}
									{#if stale(p)}<Badge tone="warning">Out of date</Badge>{/if}
									{#if p.signature_version}<span class="text-muted block font-mono text-xs">{p.signature_version}</span>{/if}
								</dd>
								{#if p.actions.includes('quick_scan') || p.last_quick_scan_at || p.last_full_scan_at}
									<dt>Quick scan</dt><dd>{#if p.last_quick_scan_at}<span title={datetime(p.last_quick_scan_at)}>{ago(p.last_quick_scan_at)}</span>{:else}<span class="text-muted">Never</span>{/if}</dd>
									<dt>Full scan</dt><dd>{#if p.last_full_scan_at}<span title={datetime(p.last_full_scan_at)}>{ago(p.last_full_scan_at)}</span>{:else}<span class="text-muted">Never</span>{/if}</dd>
								{/if}
								{#if p.tamper_protection !== null}<dt>Tamper protection</dt><dd>{@render onOff(p.tamper_protection)}</dd>{/if}
							</dl>
							{#if p.detail}<p class="text-muted mt-3 text-xs">{p.detail}</p>{/if}
						</section>
					{/each}
				</div>
				{#if products.length === 0 && s.reported_at}
					<p class="text-muted -mt-2 mb-4 text-xs">No other antivirus found on this machine.</p>
				{/if}
			{/if}

			<div class="mb-4">
			<DataTable
				id="agent-detections"
				caption="Detections"
				rows={detections}
				key={(d) => d.id}
				scroll={false}
				rowHref={(d) => `/security/detections/${d.id}`}
				columns={[
					{ id: 'threat', label: 'Threat', cell: threatCell, hideable: false },
					{ id: 'severity', label: 'Severity', cell: sevCell, from: 'sm' },
					{ id: 'status', label: 'Status', cell: statusCell },
					{ id: 'when', label: 'Detected', cell: whenCell, from: 'md' },
					{ id: 'product', label: 'Found by', cell: productCell, from: 'lg' }
				] satisfies Column<SecurityDetection>[]}
			>
				{#snippet toolbar()}
					<Input icon={Search} placeholder="Filter detections…" aria-label="Filter detections" class="w-full sm:w-64" bind:value={q} />
					<Segmented label="Show" value={show} onchange={(v) => (picked = v)} options={[{ value: 'active', label: 'Active', count: activeCount }, { value: 'all', label: 'All' }]} />
				{/snippet}
				{#snippet empty()}
					<EmptyState compact title={q ? 'No detections match' : show === 'active' ? 'No active threats' : 'Nothing detected'} description={show === 'all' && !q ? 'What the antivirus and our sensor find, and what they did about it, shows up here.' : undefined} />
				{/snippet}
			</DataTable>
			</div>

			{#if s.sensor_supported || s.quarantine.length}
				<div class="mb-4">
					<QuarantineList id="agent-quarantine" rows={s.quarantine} onchanged={() => res.reload()} />
				</div>
			{/if}

			<div class="mb-4">
				<ActionHistory actions={s.actions} title="Scans, updates and responses" emptyTitle="No scans, updates or responses started from here yet" />
			</div>

			{#if s.sensor_supported}
				<TelemetryPanel agentId={agentId} online={s.online} />
			{/if}

			{#if responding}
				<RespondDialog {agentId} {hostname} kind={responding} onclose={() => (responding = null)} ondone={() => res.reload()} />
			{/if}
		{/if}
	{/snippet}
</Async>
