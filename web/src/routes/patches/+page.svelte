<script lang="ts">
	import { Ban, Check, Clock, Download, Pencil, Plus, RefreshCw, RotateCcw, Search, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, cx, datetime, ms, num, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { categories, categoryLabel, compliancePct, rebootLabel, severities, windowLabel } from '#lib/patches.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, loadClients, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Approval, Compliance, ComplianceRow, MaintenanceWindow, PatchPolicy, PatchRun, UpdateAgent, UpdateGroup } from '#lib/types.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import InstallPatches from '#lib/components/InstallPatches.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import PatchBadge from '#lib/components/PatchBadge.svelte';
	import PolicyEditor from '#lib/components/PolicyEditor.svelte';
	import Status from '#lib/components/Status.svelte';
	import WindowEditor from '#lib/components/WindowEditor.svelte';

	const tab = $derived(param('tab', 'updates'));
	const scoped = $derived(currentClient());
	$effect(() => {
		loadClients();
	});

	// --- Updates ------------------------------------------------------------------------------
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const updates = resource(() =>
		tab === 'updates'
			? api.get<{ items: UpdateGroup[]; total: number; truncated: boolean }>(
					`/patches${qs({ client_id: clientId(), q: param('q'), severity: param('severity'), category: param('category'), approval: param('approval'), os: param('os'), state: param('show') === 'all' ? 'all' : null })}`
				)
			: Promise.resolve(null)
	);
	liveReload(() => tab === 'updates' && updates.reload(), (e) => e.type === 'patches', { debounceMs: 2000, pollMs: 30000 });
	let selected = $state(new Set<string>());
	const filtered = $derived(!!(param('q') || param('severity') || param('category') || param('approval') || param('os')));

	async function decideFleet(decision: Approval, ids: string[], agentIds?: string[]) {
		const where = agentIds ? plural(agentIds.length, 'agent') : scoped ? `every ${scoped.name} agent` : 'every agent you can see';
		if (!agentIds && decision !== 'approved') {
			const ok = await confirmAction({
				title: decision === 'declined' ? `Decline ${plural(ids.length, 'update')}?` : `Reset ${plural(ids.length, 'update')} to the policy?`,
				message: decision === 'declined'
					? `They won't be installed on ${where} unless someone approves them again. Compliance ignores declined updates.`
					: `Manual approvals and declines on ${where} are forgotten; the patch policy decides again.`,
				confirmLabel: decision === 'declined' ? 'Decline' : 'Reset'
			});
			if (!ok) return;
		}
		const ok = await attempt(async () => {
			const r = await api.post<{ changed: number; agents: number }>('/patches/approval', { decision, update_ids: ids, agent_ids: agentIds, client_id: agentIds ? null : clientId() || null });
			return r;
		}, `${decision === 'approved' ? 'Approved' : decision === 'declined' ? 'Declined' : 'Reset'} ${plural(ids.length, 'update')} on ${where}.`);
		if (ok) {
			selected = new Set();
			updates.reload();
			detailAgents.reload();
		}
	}

	// The drawer: one update's agents.
	const openId = $derived(param('update'));
	const openUpdate = $derived(updates.data?.items.find((u) => u.update_id === openId));
	const detailAgents = resource(() => (openId ? api.get<UpdateAgent[]>(`/patches/agents${qs({ update_id: openId, client_id: clientId() })}`) : Promise.resolve([] as UpdateAgent[])));
	let drawerSel = $state(new Set<string>());
	let installing = $state<{ agentIds: string[]; updateIds: string[] | null; summary: string } | null>(null);

	// --- Compliance ---------------------------------------------------------------------------
	const compliance = resource(() => (tab === 'compliance' ? api.get<Compliance>(`/patches/compliance${qs({ client_id: clientId() })}`) : Promise.resolve(null)));
	liveReload(() => tab === 'compliance' && compliance.reload(), (e) => e.type === 'patches', { debounceMs: 3000, pollMs: 60000 });

	// --- Policies -----------------------------------------------------------------------------
	const policies = resource(() => (tab === 'policies' ? api.get<PatchPolicy[]>('/patch-policies') : Promise.resolve(null)));
	const windows = resource(() => (tab === 'policies' ? api.get<MaintenanceWindow[]>('/patch-windows') : Promise.resolve(null)));
	let editing = $state<{ policy: PatchPolicy | null } | null>(null);
	let editingWindow = $state<MaintenanceWindow | null>(null);
	const shownPolicies = $derived((policies.data ?? []).filter((p) => !clientId() || !p.client_id || p.client_id === clientId()));
	const shownWindows = $derived((windows.data ?? []).filter((w) => !clientId() || w.client_id === clientId()));
	async function removePolicy(p: PatchPolicy) {
		const ok = await confirmAction({
			title: `Delete the policy for ${p.site_name ? `${p.client_name} › ${p.site_name}` : p.client_name}?`,
			message: `Its ${plural(p.agents, 'agent')} fall back to the ${p.site_id ? 'client’s policy, or the MSP-wide one' : 'MSP-wide policy'}. Manual approvals are kept.`,
			confirmLabel: 'Delete policy',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/patch-policies/${p.id}`), 'Policy deleted.'))) policies.reload();
	}
	function canEdit(p: PatchPolicy) {
		return p.client_id ? can('technician') : can('admin');
	}

	// --- History ------------------------------------------------------------------------------
	const runFilter = $derived(param('status', ''));
	const runs = resource(() =>
		tab === 'history' ? api.get<PatchRun[]>(`/patch-runs${qs({ client_id: clientId(), agent_id: param('agent'), status: runFilter || null, limit: 200 })}`) : Promise.resolve(null)
	);
	liveReload(() => tab === 'history' && runs.reload(), (e) => e.type === 'patches', { debounceMs: 1000 });

	function pctText(c: number, s: number) {
		const p = compliancePct(c, s);
		return p === null ? '–' : `${p}%`;
	}
	function runResult(r: PatchRun): string {
		if (r.status === 'sent') return r.progress ?? `${r.stage ?? 'starting'}…`;
		if (r.status === 'queued') return 'Waiting for the agent';
		if (r.status === 'lost' || r.status === 'expired' || r.status === 'cancelled' || (r.error && !r.succeeded)) return r.error ?? '';
		return `${r.succeeded} of ${r.updates} installed${r.rebooting ? ', restarting' : r.reboot_required ? ', restart pending' : ''}`;
	}
</script>

<svelte:head><title>Patches</title></svelte:head>

<PageHeader title="Patches">
	{#snippet actions()}
		{#if tab === 'policies' && can('technician')}<Button variant="primary" icon={Plus} onclick={() => (editing = { policy: null })}>New policy</Button>{/if}
	{/snippet}
</PageHeader>

<Tabs
	label="Patch sections"
	class="mb-3"
	value={tab}
	onchange={(v) => setParams({ tab: v === 'updates' ? null : v, update: null, status: null, agent: null }, { push: true })}
	items={[
		{ value: 'updates', label: 'Updates', count: updates.data ? `${num(updates.data.total)}` : undefined },
		{ value: 'compliance', label: 'Compliance' },
		{ value: 'policies', label: 'Policies & windows' },
		{ value: 'history', label: 'Install history' }
	]}
/>

{#if tab === 'updates'}
	{#snippet titleCell(u: UpdateGroup)}
		<button type="button" class="hover:text-accent text-left font-medium break-words" onclick={(e) => { e.stopPropagation(); setParams({ update: u.update_id }); }}>{u.title}</button>
		<div class="text-muted mt-0.5 flex flex-wrap gap-x-2 text-xs">
			{#if u.kb}<span class="font-mono">{u.kb}</span>{/if}
			<span class="lg:hidden">{categoryLabel(u.category)}</span>
			{#if u.requires_reboot}<span>needs restart</span>{/if}
		</div>
	{/snippet}
	{#snippet sevCell(u: UpdateGroup)}<PatchBadge kind="severity" value={u.severity} />{/snippet}
	{#snippet catCell(u: UpdateGroup)}<span class="text-muted whitespace-nowrap">{categoryLabel(u.category)}</span>{/snippet}
	{#snippet missingCell(u: UpdateGroup)}
		<span class="tabular whitespace-nowrap">{num(u.missing)}</span>{#if u.failed}<span class="text-danger ml-1 text-xs whitespace-nowrap">{u.failed} failed</span>{/if}
	{/snippet}
	{#snippet approvalCell(u: UpdateGroup)}
		<span class="inline-flex flex-wrap gap-1">
			{#if u.approved}<Badge tone="success">{num(u.approved)} approved</Badge>{/if}
			{#if u.pending}<Badge>{num(u.pending)} not approved</Badge>{/if}
			{#if u.declined}<Badge>{num(u.declined)} declined</Badge>{/if}
			{#if !u.missing}<Badge tone="success">Installed everywhere</Badge>{/if}
		</span>
	{/snippet}
	{#snippet installedCell(u: UpdateGroup)}<span class="text-muted tabular">{num(u.installed)}</span>{/snippet}
	{#snippet sizeCell(u: UpdateGroup)}<span class="text-muted tabular">{u.size ? bytes(u.size) : '–'}</span>{/snippet}
	{#snippet seenCell(u: UpdateGroup)}<span class="text-muted whitespace-nowrap" title={datetime(u.first_seen_at)}>{ago(u.first_seen_at)}</span>{/snippet}

	{#if updates.error && !updates.data}
		<div class="card"><ErrorState error={updates.error} onretry={() => updates.reload()} /></div>
	{:else}
		<DataTable
			id="patch-updates"
			caption="Updates across agents"
			rows={updates.data?.items ?? []}
			key={(u) => u.update_id}
			loading={updates.loading}
			busy={updates.busy}
			bind:selected
			activeFilters={[param('severity'), param('category'), param('approval'), param('os')].filter(Boolean).length}
			columns={[
				{ id: 'title', label: 'Update', cell: titleCell, hideable: false },
				{ id: 'severity', label: 'Severity', cell: sevCell, from: 'sm' },
				{ id: 'category', label: 'Category', cell: catCell, from: 'lg' },
				{ id: 'missing', label: 'Missing on', cell: missingCell, align: 'right' },
				{ id: 'approval', label: 'Approval', cell: approvalCell, from: 'md' },
				{ id: 'installed', label: 'Installed on', cell: installedCell, align: 'right', from: 'xl' },
				{ id: 'size', label: 'Size', cell: sizeCell, align: 'right', from: 'xl', defaultHidden: true },
				{ id: 'seen', label: 'First seen', cell: seenCell, align: 'right', from: 'lg' }
			] satisfies Column<UpdateGroup>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="Title, KB or package…" aria-label="Search updates" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
			{/snippet}
			{#snippet filters()}
				<Select aria-label="Severity" class="w-full sm:w-auto" value={param('severity')} onchange={(e) => setParams({ severity: e.currentTarget.value })}
					options={[{ value: '', label: 'Any severity' }, { value: 'critical,important', label: 'Critical & important' }, ...severities.map((s) => ({ value: s.value, label: s.label }))]} />
				<Select aria-label="Category" class="w-full sm:w-auto" value={param('category')} onchange={(e) => setParams({ category: e.currentTarget.value })}
					options={[{ value: '', label: 'Any category' }, ...categories.map((c) => ({ value: c.value, label: c.label }))]} />
				<Select aria-label="Approval" class="w-full sm:w-auto" value={param('approval')} onchange={(e) => setParams({ approval: e.currentTarget.value })}
					options={[{ value: '', label: 'Any approval' }, { value: 'pending', label: 'Needs a decision' }, { value: 'approved', label: 'Approved' }, { value: 'declined', label: 'Declined' }]} />
				<Select aria-label="Operating system" class="w-full sm:w-auto" value={param('os')} onchange={(e) => setParams({ os: e.currentTarget.value })}
					options={[{ value: '', label: 'Any OS' }, { value: 'windows', label: 'Windows' }, { value: 'linux', label: 'Linux' }, { value: 'macos', label: 'macOS' }]} />
				<Segmented label="Include installed" value={param('show') === 'all' ? 'all' : 'missing'} onchange={(v) => setParams({ show: v === 'all' ? 'all' : null })} options={[{ value: 'missing', label: 'Outstanding' }, { value: 'all', label: 'All' }]} />
			{/snippet}
			{#snippet bulk()}
				{#if can('technician')}
					<Button size="sm" variant="primary" icon={Check} onclick={() => decideFleet('approved', [...selected])}>Approve</Button>
					<Button size="sm" icon={Ban} onclick={() => decideFleet('declined', [...selected])}>Decline</Button>
					<Button size="sm" variant="ghost" icon={RotateCcw} onclick={() => decideFleet('pending', [...selected])}>Reset to policy</Button>
				{/if}
			{/snippet}
			{#snippet empty()}
				{#if filtered}
					<EmptyState title="No updates match" description="Try clearing the filters.">
						{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, severity: null, category: null, approval: null, os: null }); }}>Clear filters</Button>{/snippet}
					</EmptyState>
				{:else}
					<EmptyState title="Everything is up to date" description="No agent{scoped ? ` of ${scoped.name}` : ''} reports outstanding updates. Agents scan when they connect and every 12 hours." />
				{/if}
			{/snippet}
			{#snippet footer()}
				{#if updates.data?.truncated}<p class="text-muted px-3 py-2 text-xs">Showing the first 500 of {num(updates.data.total)} updates; narrow the filters.</p>{/if}
				{#if can('technician') && selected.size}<p class="text-muted px-3 py-2 text-xs">Decisions apply to {scoped ? `every ${scoped.name} agent` : 'every agent you can see'} that reports the update. Open an update to decide per agent.</p>{/if}
			{/snippet}
		</DataTable>
	{/if}

	<Drawer open={!!openId} title="Update" side="right" width="w-[44rem]" onclose={() => setParams({ update: null })}>
		{#if openId}
			<div class="space-y-4 px-4 pb-6">
				<div>
					<h2 class="text-base font-semibold break-words">{openUpdate?.title ?? openId}</h2>
					<div class="text-muted mt-1 flex flex-wrap items-center gap-2 text-xs">
						{#if openUpdate}<PatchBadge kind="severity" value={openUpdate.severity} /><span>{categoryLabel(openUpdate.category)}</span>{/if}
						{#if openUpdate?.kb}<span class="font-mono">{openUpdate.kb}</span>{/if}
						<span class="font-mono break-all">{openId}</span>
					</div>
				</div>
				{#snippet agentCell(a: UpdateAgent)}
					<a class="hover:text-accent font-medium" href="/agents/{a.agent_id}?tab=patches">{a.hostname}</a>
					<div class="text-muted flex flex-wrap items-center gap-x-2 text-xs"><Status online={a.online} /><span>{a.client_name} › {a.site_name}</span></div>
					{#if a.last_error && a.state === 'failed'}<div class="text-danger text-xs">{a.last_error}</div>{/if}
				{/snippet}
				{#snippet aStateCell(a: UpdateAgent)}<PatchBadge kind="state" value={a.state} />{/snippet}
				{#snippet aApprovalCell(a: UpdateAgent)}<PatchBadge kind="approval" value={a.approval} title={a.approval_manual ? `By ${a.approved_by_name ?? 'a user'}` : 'By the policy'} />{/snippet}
				{#snippet aVersionCell(a: UpdateAgent)}<span class="text-muted font-mono text-xs">{a.current_version && a.version ? `${a.current_version} → ${a.version}` : (a.version ?? '–')}</span>{/snippet}
				<DataTable
					id="patch-update-agents"
					caption="Agents with this update"
					rows={detailAgents.data ?? []}
					key={(a) => a.agent_id}
					loading={detailAgents.loading}
					bind:selected={drawerSel}
					scroll={false}
					columns={[
						{ id: 'agent', label: 'Agent', cell: agentCell, hideable: false },
						{ id: 'state', label: 'State', cell: aStateCell },
						{ id: 'approval', label: 'Approval', cell: aApprovalCell },
						{ id: 'version', label: 'Version', cell: aVersionCell, from: 'md', defaultHidden: !detailAgents.data?.some((a) => a.version) }
					] satisfies Column<UpdateAgent>[]}
				>
					{#snippet bulk(n)}
						{#if can('technician')}
							<Button size="sm" icon={Check} onclick={() => decideFleet('approved', [openId], [...drawerSel])}>Approve</Button>
							<Button size="sm" icon={Ban} onclick={() => decideFleet('declined', [openId], [...drawerSel])}>Decline</Button>
							<Button size="sm" variant="primary" icon={Download} onclick={() => (installing = { agentIds: [...drawerSel], updateIds: [openId], summary: `${openUpdate?.title ?? openId} on ${plural(n, 'agent')}` })}>Install now</Button>
						{/if}
					{/snippet}
					{#snippet empty()}<EmptyState compact title="No agents report this update" />{/snippet}
				</DataTable>
			</div>
		{/if}
	</Drawer>
{:else if tab === 'compliance'}
	<Async res={compliance}>
		{#snippet children(c)}
			{#if c}
				{@const t = c.totals}
				<div class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
					<div class="card p-3">
						<div class="text-muted text-xs font-medium">Fully patched</div>
						<div class="mt-1 text-2xl leading-none font-semibold tabular">{pctText(t.compliant, t.scanned)}<span class="text-muted ml-1 text-sm font-normal">{num(t.compliant)} of {num(t.scanned)}</span></div>
					</div>
					<Stat label="Missing security updates" value={t.agents_missing_security} tone="danger" />
					<Stat label="Outstanding updates" value={t.missing} tone="warning" />
					<Stat label="Restart pending" value={t.reboot_pending} tone="warning" />
					<Stat label="Failed installs" value={t.failed} tone="danger" />
					<Stat label="Installed (30 days)" value={t.installed_30d} />
				</div>
				{#if t.agents > t.supported || t.scan_errors}
					<p class="text-muted mb-3 text-xs">
						{#if t.agents > t.supported}{plural(t.agents - t.supported, 'agent')} can’t be patched until updated to a newer agent version. {/if}
						{#if t.scan_errors}{plural(t.scan_errors, 'agent')} failed their last scan.{/if}
					</p>
				{/if}
				{#snippet nameCell(r: ComplianceRow)}
					{#if c.by === 'client'}<a class="hover:text-accent font-medium" href={withClient('/patches?tab=compliance', r.id)}>{r.name}</a>{:else}<span class="font-medium">{r.name}</span>{/if}
				{/snippet}
				{#snippet pctCell(r: ComplianceRow)}
					{@const p = compliancePct(r.compliant, r.scanned)}
					<div class="flex items-center justify-end gap-2">
						<div class="bg-sunken hidden h-1.5 w-20 overflow-hidden rounded-full sm:block" aria-hidden="true">
							<div class={cx('h-full rounded-full', p === null ? '' : p >= 95 ? 'bg-success' : p >= 75 ? 'bg-warning' : 'bg-danger')} style="width: {p ?? 0}%"></div>
						</div>
						<span class="tabular w-10 text-right">{p === null ? '–' : `${p}%`}</span>
					</div>
				{/snippet}
				{#snippet ofCell(r: ComplianceRow)}<span class="text-muted tabular whitespace-nowrap">{num(r.compliant)} / {num(r.scanned)}{#if r.agents > r.scanned}{' '}<span class="text-muted">({r.agents - r.scanned} not scanned)</span>{/if}</span>{/snippet}
				{#snippet secCell(r: ComplianceRow)}<span class={cx('tabular', r.agents_missing_security > 0 && 'text-danger font-medium')}>{num(r.agents_missing_security)}</span>{/snippet}
				{#snippet missCell(r: ComplianceRow)}<span class="tabular">{num(r.missing)}</span>{/snippet}
				{#snippet rebootCell(r: ComplianceRow)}<span class={cx('tabular', r.reboot_pending > 0 && 'text-warning')}>{num(r.reboot_pending)}</span>{/snippet}
				{#snippet failCell(r: ComplianceRow)}<span class={cx('tabular', r.failed > 0 && 'text-danger')}>{num(r.failed)}</span>{/snippet}
				{#snippet scanCell(r: ComplianceRow)}<span class="text-muted whitespace-nowrap" title="Oldest successful scan">{r.oldest_scan ? ago(r.oldest_scan) : '–'}</span>{/snippet}
				<DataTable
					id="patch-compliance"
					caption={c.by === 'client' ? 'Compliance by client' : 'Compliance by site'}
					rows={c.rows}
					key={(r) => r.id}
					scroll={false}
					columns={[
						{ id: 'name', label: c.by === 'client' ? 'Client' : 'Site', cell: nameCell, hideable: false },
						{ id: 'pct', label: 'Fully patched', cell: pctCell, align: 'right' },
						{ id: 'of', label: 'Agents', cell: ofCell, align: 'right', from: 'md' },
						{ id: 'security', label: 'Missing security', cell: secCell, align: 'right', from: 'sm' },
						{ id: 'missing', label: 'Outstanding', cell: missCell, align: 'right', from: 'lg' },
						{ id: 'reboot', label: 'Restart pending', cell: rebootCell, align: 'right', from: 'lg' },
						{ id: 'failed', label: 'Failed', cell: failCell, align: 'right', from: 'xl' },
						{ id: 'scan', label: 'Oldest scan', cell: scanCell, align: 'right', from: 'xl' }
					] satisfies Column<ComplianceRow>[]}
				>
					{#snippet empty()}<EmptyState compact title="No agents yet" />{/snippet}
					{#snippet footer()}<p class="text-muted px-3 py-2 text-xs">An agent is fully patched when its last scan found nothing outstanding except declined updates. Worst first.</p>{/snippet}
				</DataTable>
			{/if}
		{/snippet}
	</Async>
{:else if tab === 'policies'}
	<section class="card mb-6" aria-label="Patch policies">
		<header class="border-border border-b px-4 py-2.5">
			<h2 class="text-sm font-semibold">Policies</h2>
			<p class="text-muted text-xs">The most specific one applies to each agent: site, then client, then MSP-wide.</p>
		</header>
		<Async res={policies} compact>
			{#snippet children()}
				<ul class="divide-border divide-y">
					{#each shownPolicies as p (p.id)}
						<li class="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3">
							<div class="min-w-0 flex-1">
								<div class="text-sm font-medium">
									{#if p.site_name}{p.client_name} › {p.site_name}{:else if p.client_name}{p.client_name}{:else}MSP-wide{/if}
									<span class="text-muted ml-1 text-xs font-normal">{plural(p.agents, 'agent')}</span>
								</div>
								<div class="text-muted mt-1 flex flex-wrap gap-1.5 text-xs">
									{#each p.auto_approve_categories as c (c)}<Badge tone="accent">{categoryLabel(c)}</Badge>{/each}
									{#each p.auto_approve_severities as s (s)}<Badge tone="accent">{severities.find((x) => x.value === s)?.label ?? s} severity</Badge>{/each}
									{#if !p.auto_approve_categories.length && !p.auto_approve_severities.length}<Badge>Approves nothing automatically</Badge>{/if}
									{#if p.deferral_days}<Badge icon={Clock}>Deferred {plural(p.deferral_days, 'day')}</Badge>{/if}
									<Badge tone={p.auto_install ? 'success' : 'neutral'}>{p.auto_install ? 'Installs automatically' : 'Manual installs'}</Badge>
									<Badge tone={p.reboot_policy === 'never' ? 'neutral' : 'warning'}>{rebootLabel(p.reboot_policy)}</Badge>
								</div>
								<p class="text-muted mt-1 text-xs">Updated {ago(p.updated_at)}{p.updated_by_name ? ` by ${p.updated_by_name}` : ''}</p>
							</div>
							{#if canEdit(p)}
								<div class="flex gap-1">
									<Button size="sm" icon={Pencil} onclick={() => (editing = { policy: p })}>Edit</Button>
									{#if p.client_id}<IconButton icon={Trash2} label="Delete policy" size="sm" onclick={() => removePolicy(p)} />{/if}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/snippet}
		</Async>
	</section>

	<section class="card" aria-label="Maintenance windows">
		<header class="border-border border-b px-4 py-2.5">
			<h2 class="text-sm font-semibold">Maintenance windows</h2>
			<p class="text-muted text-xs">Automatic installs start only inside a site’s window. Sites without one install as soon as updates are eligible.</p>
		</header>
		{#snippet siteCell(w: MaintenanceWindow)}<span class="font-medium">{w.site_name}</span>{#if !scoped}<span class="text-muted block text-xs">{w.client_name}</span>{/if}{/snippet}
		{#snippet winCell(w: MaintenanceWindow)}<span class={w.days?.length ? '' : 'text-muted'}>{windowLabel(w)}</span>{/snippet}
		{#snippet openCell(w: MaintenanceWindow)}
			{#if !w.days?.length}<span class="text-muted">–</span>{:else if w.open_now}<Badge tone="success" dot>Open now</Badge>{:else}<span class="text-muted whitespace-nowrap">{datetime(w.next_start)}</span>{/if}
		{/snippet}
		{#snippet agentsCell(w: MaintenanceWindow)}<span class="text-muted tabular">{num(w.agents)}</span>{/snippet}
		{#snippet editCell(w: MaintenanceWindow)}{#if can('technician')}<Button size="sm" variant="ghost" icon={Pencil} onclick={() => (editingWindow = w)}>{w.days?.length ? 'Edit' : 'Set'}</Button>{/if}{/snippet}
		<DataTable
			id="patch-windows"
			caption="Maintenance windows by site"
			rows={shownWindows}
			key={(w) => w.site_id}
			loading={windows.loading}
			scroll={false}
			columns={[
				{ id: 'site', label: 'Site', cell: siteCell, hideable: false },
				{ id: 'window', label: 'Window', cell: winCell },
				{ id: 'open', label: 'Next', cell: openCell, from: 'sm' },
				{ id: 'agents', label: 'Agents', cell: agentsCell, align: 'right', from: 'md' },
				{ id: 'edit', label: 'Edit', cell: editCell, align: 'right', hideable: false }
			] satisfies Column<MaintenanceWindow>[]}
		>
			{#snippet empty()}<EmptyState compact title="No sites yet" />{/snippet}
		</DataTable>
	</section>
{:else if tab === 'history'}
	{#snippet startedCell(r: PatchRun)}<a class="hover:text-accent whitespace-nowrap" href="/patches/runs/{r.id}">{datetime(r.created_at)}</a>{/snippet}
	{#snippet agentCell(r: PatchRun)}<a class="hover:text-accent font-medium" href="/agents/{r.agent_id}?tab=patches">{r.hostname}</a>{#if !scoped}<span class="text-muted block text-xs">{r.client_name}</span>{/if}{/snippet}
	{#snippet statusCell(r: PatchRun)}<span class="inline-flex items-center gap-1.5"><PatchBadge kind="run" value={r.status} />{#if r.status === 'sent' && r.percent != null}<span class="text-muted text-xs tabular">{r.percent}%</span>{/if}</span>{/snippet}
	{#snippet resultCell(r: PatchRun)}<span class="text-muted line-clamp-2 text-xs">{runResult(r)}</span>{/snippet}
	{#snippet byCell(r: PatchRun)}<span class="text-muted whitespace-nowrap">{r.trigger === 'policy' ? 'Policy' : (r.created_by_name ?? '–')}</span>{/snippet}
	{#snippet durCell(r: PatchRun)}<span class="text-muted tabular">{r.duration_ms != null ? ms(r.duration_ms) : '–'}</span>{/snippet}
	<DataTable
		id="patch-runs"
		caption="Install history"
		rows={runs.data ?? []}
		key={(r) => r.id}
		loading={runs.loading}
		busy={runs.busy}
		rowHref={(r) => `/patches/runs/${r.id}`}
		columns={[
			{ id: 'started', label: 'Started', cell: startedCell, hideable: false },
			{ id: 'agent', label: 'Agent', cell: agentCell },
			{ id: 'status', label: 'Status', cell: statusCell },
			{ id: 'result', label: 'Result', cell: resultCell, from: 'md' },
			{ id: 'by', label: 'By', cell: byCell, from: 'lg' },
			{ id: 'duration', label: 'Duration', cell: durCell, align: 'right', from: 'lg' }
		] satisfies Column<PatchRun>[]}
	>
		{#snippet toolbar()}
			<Segmented label="Status" value={runFilter || 'all'} onchange={(v) => setParams({ status: v === 'all' ? null : v })}
				options={[{ value: 'all', label: 'All' }, { value: 'active', label: 'Active' }, { value: 'failed,partial,lost', label: 'Problems' }]} />
			{#if param('agent')}<Button size="sm" variant="ghost" icon={RefreshCw} onclick={() => setParams({ agent: null })}>Show every agent</Button>{/if}
		{/snippet}
		{#snippet empty()}<EmptyState compact title="No installs yet" description="Installs started by hand or by a policy show up here." />{/snippet}
	</DataTable>
{/if}

{#if editing}
	<PolicyEditor policy={editing.policy} taken={(policies.data ?? []).filter((p) => p.client_id).map((p) => `${p.client_id}:${p.site_id ?? ''}`)} onclose={() => (editing = null)} onsaved={() => policies.reload()} />
{/if}
{#if editingWindow}
	<WindowEditor window={editingWindow} onclose={() => (editingWindow = null)} onsaved={() => windows.reload()} />
{/if}
{#if installing}
	<InstallPatches agentIds={installing.agentIds} updateIds={installing.updateIds} summary={installing.summary} onclose={() => (installing = null)} ondone={() => { drawerSel = new Set(); detailAgents.reload(); updates.reload(); }} />
{/if}
