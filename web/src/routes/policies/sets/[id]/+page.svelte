<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ArrowLeft, Copy, FolderPlus, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { datetime, num, osLabels, plural } from '#lib/format.js';
	import { describeCron, describePolicy } from '#lib/monitoring/labels.js';
	import { paged } from '#lib/paged.svelte.js';
	import { describeAutomation, moduleLabels, overriddenFields, ownerLabel, reasonLabels, ROOT_SET, sections, setHref } from '#lib/policy/policy.js';
	import type { Category, ItemView, Module, SetAgent, SetDetail } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { wantLabels, type SoftwarePackage, type Want } from '#lib/software.js';
	import type { PolicyKind, Script, Severity } from '#lib/types.js';
	import { param, setParams, sortState } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import SubNav from '#lib/ui/SubNav.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Status from '#lib/components/Status.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import ItemEditor from '#lib/components/policy/ItemEditor.svelte';
	import PolicyStatus from '#lib/components/policy/PolicyStatus.svelte';
	import SetDialog from '#lib/components/policy/SetDialog.svelte';
	import SetTree from '#lib/components/policy/SetTree.svelte';

	const id = $derived(page.params.id!);
	const section = $derived(param('section', 'alerts'));
	const itemId = $derived(param('item'));
	const res = resource(() => api.get<SetDetail>(`/policy-sets/${id}`), { keep: false });
	const categories = resource(() => api.get<Category[]>('/device-categories'));
	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const packages = resource(() => api.get<SoftwarePackage[]>('/software/packages'));
	let dialog = $state<'new' | 'edit' | 'duplicate' | null>(null);

	const moduleOf = $derived(sections.find((s) => s.value === section)?.module as Module | undefined);
	const items = (s: SetDetail, m: Module) => s.policies.filter((p) => p.module === m);

	const deviceSort = sortState('hostname');
	// paged() adds the page size; the list is only shown in the Devices section.
	const devices = paged<SetAgent>(() => `/policy-sets/${id}/agents?sort=${deviceSort.key}&dir=${deviceSort.dir}`);

	function open(item: string | null, extra: Record<string, string | null> = {}) {
		setParams({ item, kind: null, ...extra }, { push: true });
	}
	async function remove(s: SetDetail) {
		const ok = await confirmAction({
			title: `Delete ${s.name}?`,
			message: s.items ? `Its ${plural(s.items, 'policy', 'policies')} go with it; their open alerts close without notifications.` : 'Its overrides go with it.',
			confirmLabel: 'Delete set',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/policy-sets/${s.id}`), `${s.name} deleted.`))) await goto(setHref(s.parent_id ?? ROOT_SET, 'children'));
	}
	async function toggle(v: ItemView, on: boolean) {
		await attempt(async () => {
			await api.put(`/policy-items/${v.id}`, { enabled: on });
			res.reload();
		}, `${v.name} ${on ? 'enabled' : 'disabled'}.`);
	}

	const catNames = (ids: string[]) => ids.map((c) => categories.data?.find((x) => x.id === c)?.name).filter(Boolean).join(', ');
	const scriptName = (sid: unknown) => scripts.data?.find((s) => s.id === sid)?.name ?? 'Script';
	const packageName = (pid: unknown) => packages.data?.find((p) => p.id === pid)?.name ?? 'Package';
	/** The sections that list several items, each a module of its own. */
	const listModules: Record<string, Module> = { alerts: 'alert', schedules: 'schedule', software: 'software', automations: 'automation' };
	const listModule = $derived(listModules[section]);
	const limitText = (v: ItemView) => (v.limit.client_name ? `${v.limit.client_name}${v.limit.site_name ? ` › ${v.limit.site_name}` : ''}` : '');
	const canNewChild = $derived(can('technician'));
	const canAdd = $derived(!!res.data && (res.data.client_id ? res.data.editable : can('technician')));
</script>

<svelte:head><title>{res.data?.name ?? 'Policy set'}</title></svelte:head>

<Async res={res}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-64" /></div>
		<div class="grid gap-4 lg:grid-cols-[11rem_1fr]"><Skeleton class="h-48 w-full" /><div class="card space-y-2 p-4"><Skeleton lines={8} /></div></div>
	{/snippet}
	{#snippet children(s)}
		{@const counts = { alert: items(s, 'alert').length, schedule: items(s, 'schedule').length, software: items(s, 'software').length, automation: items(s, 'automation').length }}
		{@const singleOverride = (m: Module) => items(s, m)[0]?.status === 'overridden'}
		<PageHeader
			title={s.name}
			crumbs={[{ label: 'Policies', href: '/policies' }, ...s.chain.slice(0, -1).map((c) => ({ label: c.name, href: setHref(c.id) })), { label: s.name }]}
			description={s.description || undefined}
			menu={[
				...(s.editable ? [{ label: 'Rename and describe…', icon: Pencil, onSelect: () => (dialog = 'edit') }] : []),
				...(s.id !== ROOT_SET && can('technician') ? [{ label: 'Duplicate…', icon: Copy, onSelect: () => (dialog = 'duplicate') }] : []),
				...(s.editable && !s.builtin ? [{ separator: true } as const, { label: 'Delete set…', icon: Trash2, danger: true, onSelect: () => remove(s) }] : [])
			]}
		>
			{#snippet subtitle()}
				<Badge tone={s.client_id ? 'neutral' : 'accent'}>{ownerLabel(s)}</Badge>
				{#if s.builtin}<span>Built-in</span>{/if}
				<a class="hover:text-fg" href="?section=devices">{s.devices === 1 ? '1 device uses it' : `${num(s.devices)} devices use it`}</a>
				{#if s.default_for.length && categories.data}<span>Default for {catNames(s.default_for)}</span>{/if}
			{/snippet}
			{#snippet actions()}
				{#if canNewChild}<Button icon={FolderPlus} onclick={() => (dialog = 'new')}>New child set</Button>{/if}
			{/snippet}
		</PageHeader>

		<div class="lg:grid lg:grid-cols-[11rem_minmax(0,1fr)] lg:gap-6">
			<SubNav
				label="Policy set sections"
				param="section"
				class="mb-4 lg:sticky lg:top-4 lg:mb-0 lg:self-start"
				value={section}
				first="alerts"
				onchange={(v) => setParams({ section: v === 'alerts' ? null : v, item: null, kind: null }, { push: true })}
				groups={[
					{ label: 'Policies', items: [
						{ value: 'alerts', label: 'Alerts', count: counts.alert ? num(counts.alert) : undefined },
						{ value: 'schedules', label: 'Scheduled scripts', count: counts.schedule ? num(counts.schedule) : undefined },
						{ value: 'software', label: 'Software', count: counts.software ? num(counts.software) : undefined },
						{ value: 'automations', label: 'Automations', count: counts.automation ? num(counts.automation) : undefined },
						{ value: 'patching', label: 'Patching', count: singleOverride('patch') ? 'edited' : undefined, title: singleOverride('patch') ? 'Overridden in this set' : undefined },
						{ value: 'security', label: 'Security', count: singleOverride('security') ? 'edited' : undefined, title: singleOverride('security') ? 'Overridden in this set' : undefined },
						{ value: 'remote', label: 'Remote access', count: singleOverride('remote_access') ? 'edited' : undefined, title: singleOverride('remote_access') ? 'Overridden in this set' : undefined },
						{ value: 'agent', label: 'Agent', count: singleOverride('agent') ? 'edited' : undefined, title: singleOverride('agent') ? 'Overridden in this set' : undefined }
					] },
					{ label: 'Set', items: [
						{ value: 'devices', label: 'Devices', count: num(s.devices) },
						{ value: 'children', label: 'Child sets', count: s.children.length ? num(s.children.length) : undefined }
					] }
				]}
			/>
			<div class="min-w-0">
				{#if listModule && itemId}
					{@const m = listModule}
					{@const v = s.policies.find((p) => p.id === itemId)}
					<a class="text-muted hover:text-fg mb-3 inline-flex items-center gap-1 text-sm" href="?section={section}" onclick={(e) => (e.preventDefault(), open(null))}><ArrowLeft class="size-4" />All {moduleLabels[m].toLowerCase()} in {s.name}</a>
					{#if itemId === 'new'}
						{#key param('kind')}
							<ItemEditor set={s} view={null} module={m} kind={(param('kind') as PolicyKind) || 'offline'} oncreated={(c) => (res.reload(), open(c.id))} />
						{/key}
					{:else if v}
						{#key v.id}
							<ItemEditor set={s} view={v} module={m} onsaved={() => res.reload()} ondeleted={() => (res.reload(), open(null))} />
						{/key}
					{:else}
						<div class="card"><EmptyState title="Not in this set" description="That policy doesn't reach {s.name}, or was deleted." /></div>
					{/if}
				{:else if listModule}
					{@const m = listModule}
					{@const list = items(s, m)}
					{#snippet nameCell(v: ItemView)}
						<a class="hover:text-accent font-medium" href="?section={section}&item={v.id}">{v.name}</a>
						<div class="text-muted max-w-md truncate text-xs">
							{#if v.module === 'alert'}{describePolicy({ kind: v.config.kind as PolicyKind, params: (v.config.params ?? {}) as Record<string, unknown> })}{:else if v.module === 'software'}{packageName(v.config.package_id)} · {wantLabels[v.config.state as Want]}{:else if v.module === 'automation'}{describeAutomation(v.config)} · {scriptName(v.config.script_id)}{:else}{scriptName(v.config.script_id)} · {describeCron(String(v.config.cron))}{/if}
						</div>
						<div class="mt-1 md:hidden"><PolicyStatus view={v} /></div>
					{/snippet}
					{#snippet statusCell(v: ItemView)}
						<PolicyStatus view={v} />
						{#if v.status === 'overridden'}<div class="text-muted mt-0.5 max-w-56 truncate text-xs">{overriddenFields(v.override).join(', ')}</div>{/if}
					{/snippet}
					{#snippet sevCell(v: ItemView)}<SeverityBadge severity={v.config.severity as Severity} />{/snippet}
					{#snippet scopeCell(v: ItemView)}
						{#if limitText(v)}<Badge>{limitText(v)}</Badge>{:else}<span class="text-muted">Every client</span>{/if}
						{#if v.limit.excluded.length}<span class="text-muted block text-xs">except {plural(v.limit.excluded.length, 'device')}</span>{/if}
					{/snippet}
					{#snippet openCell(v: ItemView)}
						{#if v.open_alerts}<a class="text-danger font-medium hover:underline" href="/alerts?policy={v.id}">{v.open_alerts}</a>{:else}<span class="text-muted" aria-label="none">–</span>{/if}
					{/snippet}
					{#snippet runsCell(v: ItemView)}
						{#if v.runs}
							<span class="whitespace-nowrap tabular">{v.runs.succeeded} ok{#if v.runs.failed}, <span class="text-danger font-medium">{v.runs.failed} failed</span>{/if}{#if v.runs.pending + v.runs.waiting}, {v.runs.pending + v.runs.waiting} in progress{/if}</span>
						{:else}<span class="text-muted">–</span>{/if}
					{/snippet}
					{#snippet nextCell(v: ItemView)}<span class="text-muted whitespace-nowrap">{v.enabled && v.schedule?.next_run_at ? datetime(v.schedule.next_run_at) : '–'}</span>{/snippet}
					{#snippet onCell(v: ItemView)}
						{#if v.status === 'defined' && v.editable}
							<Switch checked={v.enabled} label="{v.enabled ? 'Disable' : 'Enable'} {v.name}" onchange={(c) => toggle(v, c)} />
						{:else}
							<span class={v.enabled ? '' : 'text-muted'} title={v.status === 'defined' ? undefined : 'As it applies in this set'}>{v.enabled ? 'On' : 'Off'}</span>
						{/if}
					{/snippet}
					<DataTable
						id="set-{section}"
						caption="{moduleLabels[m]} in {s.name}"
						rows={list}
						key={(v) => v.id}
						rowHref={(v) => `?section=${section}&item=${v.id}`}
						scroll={false}
						columns={[
							{ id: 'name', label: m === 'alert' ? 'Policy' : m === 'software' ? 'Requirement' : m === 'automation' ? 'Automation' : 'Scheduled script', cell: nameCell, hideable: false },
							{ id: 'status', label: 'Where it’s set', cell: statusCell, from: 'md' },
							...(m === 'alert'
								? [
										{ id: 'severity', label: 'Severity', cell: sevCell, from: 'sm' as const }
									]
								: m === 'software'
									? []
									: m === 'automation'
										? [{ id: 'runs', label: 'Runs', cell: runsCell, from: 'sm' as const }]
									: [{ id: 'next', label: 'Next run', cell: nextCell, from: 'sm' as const }]),
							{ id: 'scope', label: 'Limited to', cell: scopeCell, from: 'xl' },
							...(m === 'alert' ? [{ id: 'open', label: 'Open', cell: openCell, align: 'right' as const }] : []),
							{ id: 'on', label: 'On', cell: onCell, hideable: false, class: 'w-16' }
						] satisfies Column<ItemView>[]}
					>
						{#snippet toolbar()}
							<p class="text-muted min-w-0 flex-1 text-xs">
								{m === 'alert' ? 'Alert policies' : m === 'software' ? 'Software requirements' : m === 'automation' ? 'Automations' : 'Scripts'} defined here apply in this set and every set below it. Inherited ones can be changed here, field by field.
							</p>
							{#if canAdd}<Button size="sm" variant="primary" icon={Plus} onclick={() => open('new')}>{m === 'alert' ? 'New alert policy' : m === 'software' ? 'New software requirement' : m === 'automation' ? 'New automation' : 'New scheduled script'}</Button>{/if}
						{/snippet}
						{#snippet empty()}
							<EmptyState
								compact
								title={m === 'alert' ? 'No alert policies reach this set' : m === 'software' ? 'No software is required in this set' : m === 'automation' ? 'No automations reach this set' : 'No scheduled scripts reach this set'}
								description={m === 'alert'
									? 'A policy watches devices for one problem (offline, high CPU, a stopped service, a failed script…) and opens an alert.'
									: m === 'software'
										? 'Pick a catalog package and say whether devices using this set must have it, keep it current, or not have it. Devices install or remove it on their own, and again when they join the set.'
										: m === 'automation'
											? 'Run a saved script when something happens on a device (it enrolls, comes back online, an alert opens, a patch install needs a restart), or once on every device.'
											: 'Run a saved script on a timetable on every device using this set: nightly cleanups, weekly reports.'}
							/>
						{/snippet}
					</DataTable>
				{:else if moduleOf}
					{@const v = items(s, moduleOf)[0]}
					{#if v}
						{#key `${v.id}:${s.id}`}<ItemEditor set={s} view={v} module={moduleOf} onsaved={() => res.reload()} />{/key}
					{:else}
						<div class="card"><EmptyState title="Not visible" description="This policy doesn't reach {s.name}." /></div>
					{/if}
				{:else if section === 'devices'}
					{#snippet hostCell(a: SetAgent)}<a class="hover:text-accent font-medium" href="/agents/{a.id}?tab=policy">{a.hostname}</a><div class="text-muted text-xs sm:hidden">{a.client_name} › {a.site_name}</div>{/snippet}
					{#snippet clientCell(a: SetAgent)}<span class="text-muted">{a.client_name} › {a.site_name}</span>{/snippet}
					{#snippet catCell(a: SetAgent)}{a.category_name}<span class="text-muted block text-xs">{osLabels[a.os_family]} {a.platform}</span>{/snippet}
					{#snippet whyCell(a: SetAgent)}<span class="text-muted">{reasonLabels[a.reason]}</span>{/snippet}
					{#snippet onlineCell(a: SetAgent)}<Status online={a.online} />{/snippet}
					<DataTable
						id="set-devices"
						caption="Devices using {s.name}"
						rows={devices.rows}
						key={(a) => a.id}
						loading={devices.loading}
						busy={devices.busy}
						sort={deviceSort}
						rowHref={(a) => `/agents/${a.id}?tab=policy`}
						columns={[
							{ id: 'hostname', label: 'Device', sort: 'hostname', cell: hostCell, hideable: false },
							{ id: 'client', label: 'Client / site', sort: 'client', cell: clientCell, from: 'sm' },
							{ id: 'category', label: 'Category', cell: catCell, from: 'md' },
							{ id: 'why', label: 'Why this set', cell: whyCell },
							{ id: 'status', label: 'Status', cell: onlineCell, from: 'lg' }
						] satisfies Column<SetAgent>[]}
					>
						{#snippet toolbar()}<p class="text-muted text-xs">Devices whose own set this is. Devices using a set below it get its policies too.</p>{/snippet}
						{#snippet empty()}<EmptyState compact title="No devices use this set" description="Assign it to a client or site for a device category, pin it to a device, or make it a category's default." />{/snippet}
						{#snippet footer()}
							{#if devices.data && (devices.data.next || devices.data.prev)}
								<Pagination shown={devices.rows.length} total={devices.data.total} hasPrev={!!devices.data.prev} hasNext={!!devices.data.next} pageSize={devices.pageSize} onprev={devices.prev} onnext={devices.next} onfirst={devices.first} onpagesize={devices.setPageSize} />
							{/if}
						{/snippet}
					</DataTable>
				{:else if section === 'children'}
					<section class="card" aria-labelledby="children-h">
						<header class="panel-head">
							<div>
								<h2 id="children-h" class="panel-title">Child sets</h2>
								<p class="text-muted text-xs">They inherit every policy of {s.name}, and can override fields or add their own.</p>
							</div>
							{#if canNewChild}<Button size="sm" icon={FolderPlus} onclick={() => (dialog = 'new')}>New child set</Button>{/if}
						</header>
						{#if s.children.length}
							<SetTree rows={s.children} categories={categories.data ?? []} base={s.depth + 1} label="Child sets of {s.name}" />
						{:else}
							<EmptyState compact title="No child sets" description="Add one for a group of devices that needs something different: kiosks, SQL servers, one client's servers." />
						{/if}
					</section>
				{/if}
			</div>
		</div>

		{#if dialog}
			<SetDialog
				mode={dialog}
				set={s}
				parent={dialog === 'new' ? s : undefined}
				onclose={() => (dialog = null)}
				ondone={(r) => (dialog === 'edit' ? res.reload() : goto(setHref(r.id)))}
			/>
		{/if}
	{/snippet}
</Async>
