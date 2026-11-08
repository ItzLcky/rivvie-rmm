<script lang="ts">
	import { Bell, Download, Pencil, Play, Plus, RefreshCw, Search, Settings, Trash2 } from '@lucide/svelte';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { JobStatus } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Breadcrumbs from '#lib/ui/Breadcrumbs.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Kbd from '#lib/ui/Kbd.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Spinner from '#lib/ui/Spinner.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import Tooltip from '#lib/ui/Tooltip.svelte';
	import Chart from '#lib/components/Chart.svelte';
	import CodeEditor from '#lib/components/CodeEditor.svelte';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import Status from '#lib/components/Status.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';

	/** Every component in its states, in the current theme. Screenshotted in both by Playwright. */
	let theme = $state<'light' | 'dark'>(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');
	$effect(() => {
		document.documentElement.dataset.theme = theme;
	});

	let text = $state('web-01');
	let sel = $state('linux');
	let combo = $state('b');
	let checked = $state(true);
	let on = $state(true);
	let tab = $state('overview');
	let seg = $state<'24h' | '1h' | '7d'>('24h');
	let modal = $state(false);
	let drawer = $state(false);
	let code = $state('#!/bin/bash\n# Free space on every mount\ndf -h | awk \'NR > 1 { print $6, $5 }\'\nexit 0');

	interface Row { id: string; host: string; client: string; online: boolean; cpu: number }
	const rows: Row[] = Array.from({ length: 6 }, (_, i) => ({ id: `r${i}`, host: `host-${String(i + 1).padStart(2, '0')}`, client: ['Acme', 'Globex', 'Initech'][i % 3], online: i % 4 !== 3, cpu: (i * 17) % 100 }));
	let selected = $state(new Set(['r1']));
	let sortKey = $state('host');
	let sortDir = $state<'asc' | 'desc'>('asc');
	const sort = { get key() { return sortKey; }, get dir() { return sortDir; }, toggle: (k: string) => { sortDir = sortKey === k && sortDir === 'asc' ? 'desc' : 'asc'; sortKey = k; } };
	const sorted = $derived([...rows].sort((a, b) => (sortDir === 'asc' ? 1 : -1) * String(a[sortKey as keyof Row]).localeCompare(String(b[sortKey as keyof Row]), undefined, { numeric: true })));
	const statuses: JobStatus[] = ['queued', 'sent', 'succeeded', 'failed', 'timed_out', 'error', 'cancelled', 'lost', 'expired'];
	const series = Array.from({ length: 60 }, (_, i) => ({ t: Date.UTC(2026, 0, 1, 0, i * 5), v: 30 + 25 * Math.sin(i / 6) + ((i * 7) % 11) }));
</script>

{#snippet section(title: string)}<h2 class="text-muted mt-10 mb-3 border-b border-border pb-1 text-xs font-semibold tracking-wide uppercase">{title}</h2>{/snippet}

<div class="bg-surface min-h-dvh p-6">
	<div class="mx-auto max-w-6xl">
		<div class="flex flex-wrap items-center justify-between gap-3">
			<div><h1 class="text-xl font-semibold">UI gallery</h1><p class="text-muted text-sm">src/lib/ui and src/lib/components, every state. Dev builds only.</p></div>
			<Segmented label="Theme" value={theme} onchange={(v) => (theme = v)} options={[{ value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }]} />
		</div>

		{@render section('Buttons')}
		<div class="space-y-3">
			{#each ['md', 'sm', 'xs'] as const as size (size)}
				<div class="flex flex-wrap items-center gap-2">
					<Button variant="primary" {size} icon={Play}>Primary</Button>
					<Button {size} icon={Download}>Secondary</Button>
					<Button variant="ghost" {size}>Ghost</Button>
					<Button variant="danger" {size} icon={Trash2}>Danger</Button>
					<Button variant="danger-ghost" {size}>Danger ghost</Button>
					<Button variant="primary" {size} loading>Loading</Button>
					<Button {size} disabled>Disabled</Button>
				</div>
			{/each}
			<div class="flex items-center gap-1">
				<IconButton icon={Settings} label="Settings" />
				<IconButton icon={Pencil} label="Edit" size="sm" />
				<IconButton icon={Trash2} label="Delete" variant="danger-ghost" />
				<IconButton icon={Bell} label="Active" active />
				<IconButton icon={RefreshCw} label="Disabled" disabled />
				<Menu items={[{ heading: 'Agent' }, { label: 'Refresh inventory', icon: RefreshCw }, { label: 'Disabled item', disabled: true }, { separator: true }, { label: 'Remove…', icon: Trash2, danger: true }]} />
				<Tooltip text="A tooltip">{#snippet trigger(p)}<button {...p} class="link ml-2 text-sm">Hover or focus me</button>{/snippet}</Tooltip>
			</div>
		</div>

		{@render section('Form controls')}
		<div class="grid gap-4 md:grid-cols-3">
			<Field label="Input" id="g-in" hint="A hint under the control."><Input id="g-in" bind:value={text} /></Field>
			<Field label="With icon" id="g-icon"><Input id="g-icon" icon={Search} placeholder="Search…" /></Field>
			<Field label="Invalid" id="g-bad" error="Must be at least 12 characters"><Input id="g-bad" value="short" invalid /></Field>
			<Field label="Disabled" id="g-dis"><Input id="g-dis" value="read only" disabled /></Field>
			<Field label="Select" id="g-sel"><Select id="g-sel" bind:value={sel} options={[{ value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }]} /></Field>
			<Field label="Combobox (searchable)" id="g-combo">
				<Combobox id="g-combo" bind:value={combo} clearable items={[{ value: 'a', label: 'Acme Corp', hint: '12 agents' }, { value: 'b', label: 'Globex', hint: '40 agents' }, { value: 'c', label: 'Initech' }]} />
			</Field>
			<Field label="Textarea" id="g-ta" class="md:col-span-2"><Textarea id="g-ta" rows={2} value="One argument per line" /></Field>
			<div class="space-y-2">
				<div class="label">Checkbox and switch</div>
				<div class="flex flex-wrap gap-4">
					<Checkbox bind:checked>Checked</Checkbox>
					<Checkbox>Unchecked</Checkbox>
					<Checkbox indeterminate>Some</Checkbox>
					<Checkbox disabled>Disabled</Checkbox>
				</div>
				<div class="flex flex-wrap gap-4"><Switch bind:checked={on}>On</Switch><Switch>Off</Switch><Switch disabled>Disabled</Switch></div>
			</div>
		</div>

		{@render section('Status')}
		<div class="flex flex-wrap items-center gap-2">
			{#each ['neutral', 'accent', 'success', 'warning', 'danger', 'info'] as const as tone (tone)}<Badge {tone} dot>{tone}</Badge>{/each}
		</div>
		<div class="mt-3 flex flex-wrap items-center gap-3">
			<Status online /><Status online={false} />
			{#each ['healthy', 'attention', 'unhealthy', 'unknown'] as const as h (h)}<HealthBadge health={h} />{/each}
		</div>
		<div class="mt-3 flex flex-wrap gap-2">{#each statuses as s (s)}<JobBadge status={s} />{/each}</div>
		<div class="mt-3 flex flex-wrap gap-4"><OsBadge os="linux" name="Ubuntu 24.04" /><OsBadge os="windows" name="Windows Server 2022" /><OsBadge os="macos" /></div>
		<div class="mt-3 grid max-w-md gap-2">{#each [12, 78, 95] as v (v)}<UsageBar value={v} />{/each}</div>
		<p class="text-muted mt-3 mb-1 text-xs">Table form: numbers only, colour past 75% and 90%.</p>
		<div class="flex gap-6">{#each [12, 78, 95] as v (v)}<UsageBar bar={false} value={v} />{/each}</div>
		{@render section('KPI tiles and links')}
		<div class="grid max-w-3xl grid-cols-2 gap-3 md:grid-cols-4">
			<Stat label="Offline" value={2} of={7} tone="warning" href="#" />
			<Stat label="Need attention" value={3} tone="danger" href="#" />
			<Stat label="Failed jobs (24 h)" value={0} tone="danger" href="#" />
			<Stat label="Agents online" value={5} of={7} />
		</div>
		<div class="mt-3 flex items-center gap-4"><MoreLink href="/dev/ui">All clients</MoreLink><span class="text-muted text-sm">Inline text uses a <a class="link" href="/dev/ui">underlined link</a>.</span></div>
		<Tabs label="Example views" class="mt-3 max-w-md" value="all" onchange={() => {}} items={[{ value: 'all', label: 'All', count: 7 }, { value: 'online', label: 'Online', count: 5 }, { value: 'offline', label: 'Offline', count: 2 }, { value: 'attention', label: 'Needs attention', count: 3 }, { value: 'new', label: 'New', count: 1 }]} />

		{@render section('Navigation')}
		<Breadcrumbs items={[{ label: 'Clients', href: '#' }, { label: 'Acme', href: '#' }, { label: 'HQ', href: '#' }, { label: 'web-01' }]} />
		<div class="card mt-3 p-4">
			<PageHeader title="web-01" count={42} description="A page header with count, meta, actions and overflow menu." menu={[{ label: 'Rename', icon: Pencil }, { separator: true }, { label: 'Delete…', icon: Trash2, danger: true }]}>
				{#snippet subtitle()}<Status online size="md" /><HealthBadge health="attention" /><OsBadge os="linux" name="Ubuntu 24.04 LTS" /><span>Acme Corp › Head office</span>{/snippet}
				{#snippet actions()}<Button variant="primary" icon={Plus}>Primary action</Button>{/snippet}
			</PageHeader>
			<Tabs label="Example" value={tab} onchange={(v) => (tab = v)} items={[{ value: 'overview', label: 'Overview' }, { value: 'software', label: 'Software', count: 312 }, { value: 'jobs', label: 'Jobs' }]} />
		</div>
		<div class="mt-3 flex items-center gap-4"><Segmented label="Range" value={seg} onchange={(v) => (seg = v)} options={[{ value: '1h', label: '1h' }, { value: '24h', label: '24h' }, { value: '7d', label: '7d' }]} /><Kbd keys={['Ctrl', 'K']} /><Kbd keys={['g', 'a']} /></div>

		{@render section('Overlays and feedback')}
		<div class="flex flex-wrap gap-2">
			<Button onclick={() => (modal = true)}>Modal</Button>
			<Button onclick={() => (drawer = true)}>Drawer</Button>
			<Button onclick={() => confirmAction({ title: 'Delete Acme?', message: 'Deletes 3 sites and 40 agents.', confirmLabel: 'Delete client', danger: true, typeToConfirm: 'Acme' })}>Confirm (type to confirm)</Button>
			<Button onclick={() => toast.success('Saved.')}>Toast: success</Button>
			<Button onclick={() => toast.error('The agent is offline')}>Toast: error</Button>
			<Button onclick={() => toast.info('Update offered to 12 agents.', { action: { label: 'Undo', run: () => {} } })}>Toast: with action</Button>
		</div>
		<div class="mt-4 grid gap-4 md:grid-cols-3">
			<div class="card"><EmptyState title="No agents yet" description="An empty state with an action.">{#snippet action()}<Button size="sm" variant="primary" icon={Plus}>Enroll</Button>{/snippet}</EmptyState></div>
			<div class="card"><ErrorState error="Request failed: 502 Bad Gateway" onretry={() => {}} /></div>
			<div class="card space-y-3 p-4"><Skeleton class="h-5 w-40" /><Skeleton lines={4} /><Spinner /></div>
		</div>

		{@render section('Data')}
		{#snippet hostCell(r: Row)}<span class="font-medium">{r.host}</span>{/snippet}
		{#snippet clientCell(r: Row)}<span class="text-muted">{r.client}</span>{/snippet}
		{#snippet onlineCell(r: Row)}<Status online={r.online} />{/snippet}
		{#snippet cpuCell(r: Row)}<UsageBar bar={false} value={r.cpu} />{/snippet}
		<DataTable
			id="gallery"
			caption="Example table"
			rows={sorted}
			key={(r) => r.id}
			{sort}
			bind:selected
			scroll={false}
			columns={[
				{ id: 'host', label: 'Hostname', sort: 'host', cell: hostCell, hideable: false },
				{ id: 'client', label: 'Client', sort: 'client', cell: clientCell },
				{ id: 'online', label: 'Status', cell: onlineCell },
				{ id: 'cpu', label: 'CPU', sort: 'cpu', cell: cpuCell, align: 'right', class: 'w-24' }
			] satisfies Column<Row>[]}
		>
			{#snippet toolbar()}<Input icon={Search} placeholder="Filter…" class="w-56" />{/snippet}
			{#snippet bulk()}<Button size="sm" variant="primary" icon={Play}>Run script</Button>{/snippet}
			{#snippet footer()}<Pagination shown={6} total={1234} hasPrev={false} hasNext pageSize={50} onprev={() => {}} onnext={() => {}} onfirst={() => {}} onpagesize={() => {}} />{/snippet}
		</DataTable>
		<div class="mt-4 grid gap-4 md:grid-cols-2">
			<DataTable id="gallery-loading" caption="Loading" rows={[]} key={(r: Row) => r.id} loading scroll={false} columns={[{ id: 'host', label: 'Hostname', cell: hostCell }, { id: 'client', label: 'Client', cell: clientCell }] satisfies Column<Row>[]} />
			<DataTable id="gallery-empty" caption="Empty" rows={[]} key={(r: Row) => r.id} scroll={false} columns={[{ id: 'host', label: 'Hostname', cell: hostCell }, { id: 'client', label: 'Client', cell: clientCell }] satisfies Column<Row>[]}>
				{#snippet empty()}<EmptyState compact title="No agents match" />{/snippet}
			</DataTable>
		</div>
		<div class="card mt-4 space-y-4 p-4"><Chart label="CPU" points={series} /><Chart label="Memory" points={series.map((p) => ({ ...p, v: 100 - p.v }))} /></div>

		{@render section('Code')}
		<div class="grid gap-4 md:grid-cols-2">
			<CodeBlock label="Linux (as root)" code="curl -fsSLo rmm-agent https://rmm.example.com/api/agent-downloads/linux-x86_64?token=… && sudo ./rmm-agent enroll --install" />
			<CodeEditor bind:value={code} interpreter="bash" minHeight="8rem" />
		</div>
	</div>
</div>

{#if modal}
	<Modal title="Modal title" description="Focus is trapped inside and returns to the trigger." onclose={() => (modal = false)}>
		<Field label="Name" id="g-modal"><Input id="g-modal" value="Acme" /></Field>
		{#snippet footer()}<Button onclick={() => (modal = false)}>Cancel</Button><Button variant="primary" onclick={() => (modal = false)}>Save</Button>{/snippet}
	</Modal>
{/if}
<Drawer bind:open={drawer} title="Drawer"><p class="text-muted p-4 text-sm">Side panel content.</p></Drawer>
