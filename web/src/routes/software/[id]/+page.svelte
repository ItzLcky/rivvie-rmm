<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Download, Pencil, RefreshCw, Search, Trash2, Upload } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { bytes, num, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { opLabels, providerLabels, sourcesOf, standing, wantLabels, type SoftwareDevice, type SoftwarePackage } from '#lib/software.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import OsIcon from '#lib/components/OsIcon.svelte';
	import PackageForm from '#lib/components/software/PackageForm.svelte';
	import Status from '#lib/components/Status.svelte';

	const id = $derived(page.params.id!);
	const pkg = resource(() => api.get<SoftwarePackage>(`/software/packages/${id}`), { keep: false });
	const show = $derived(param('show', 'installed'));
	const devices = resource(() => api.get<{ items: SoftwareDevice[] }>(`/software/packages/${id}/devices${qs({ show, q: param('q') })}`));
	liveReload(() => (pkg.reload(), devices.reload()), (e) => e.type === 'software', { debounceMs: 1500, pollMs: 60000 });

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	let editing = $state(false);
	let selected = $state(new Set<string>());
	let deploy = $state<{ op: 'install' | 'upgrade' | 'uninstall' } | null>(null);
	let bootstrap = $state(false);
	let busy = $state(false);
	let fileInput = $state<HTMLInputElement>();

	const rows = $derived(devices.data?.items ?? []);
	const picked = $derived(rows.filter((d) => selected.has(d.agent_id)));

	async function remove(p: SoftwarePackage) {
		const ok = await confirmAction({
			title: `Delete ${p.name}?`,
			message: 'It leaves the catalog and its uploaded installer is removed. Devices keep what is installed. Policies that require it must be removed first.',
			confirmLabel: 'Delete package',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/software/packages/${p.id}`), `${p.name} deleted.`))) await goto('/software');
	}
	async function upload(e: Event) {
		const f = (e.currentTarget as HTMLInputElement).files?.[0];
		if (!f) return;
		busy = true;
		try {
			const form = new FormData();
			form.append('file', f);
			const r = await fetch(`/api/software/packages/${id}/installer`, { method: 'POST', body: form, credentials: 'same-origin' });
			const data = await r.json().catch(() => null);
			if (!r.ok) throw new Error(data?.error ?? (r.status === 413 ? 'that file is larger than the upload limit (RMM_ATTACHMENT_MAX_MB)' : r.statusText));
			pkg.set(data as SoftwarePackage);
			toast.success('Installer uploaded.');
			devices.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
			if (fileInput) fileInput.value = '';
		}
	}
	async function dropInstaller(p: SoftwarePackage) {
		if (await confirmAction({ title: 'Remove the uploaded installer?', message: 'Devices can no longer install this package from the file.', confirmLabel: 'Remove', danger: true })) {
			await attempt(async () => pkg.set(await api.del<SoftwarePackage>(`/software/packages/${p.id}/installer`)), 'Installer removed.');
		}
	}
	async function run() {
		if (!deploy) return;
		busy = true;
		try {
			const r = await api.post<{ runs: unknown[]; skipped: { hostname: string; reason: string }[] }>('/software/deploy', { package_id: id, op: deploy.op, agent_ids: picked.map((d) => d.agent_id), bootstrap_choco: bootstrap });
			toast.success(`${opLabels[deploy.op]} started on ${plural(r.runs.length, 'device')}.${r.skipped.length ? ` Skipped ${r.skipped.length}: ${r.skipped[0].hostname}: ${r.skipped[0].reason}` : ''}`);
			deploy = null;
			selected = new Set();
			devices.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
	async function scan() {
		const ids = rows.map((d) => d.agent_id);
		if (ids.length && (await attempt(() => api.post('/software/scan', { agent_ids: ids }), 'Asked those devices to rescan.'))) devices.reload();
	}
</script>

<svelte:head><title>{pkg.data?.name ?? 'Software package'}</title></svelte:head>

<Async res={pkg}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-64" /></div>
		<div class="card space-y-2 p-4"><Skeleton lines={5} /></div>
	{/snippet}
	{#snippet children(p)}
		<PageHeader
			title={p.name}
			crumbs={[{ label: 'Software', href: '/software' }, { label: p.name }]}
			description={p.description || undefined}
			menu={[
				...(can('technician') ? [{ label: 'Edit package…', icon: Pencil, onSelect: () => (editing = true) }] : []),
				...(can('technician') ? [{ separator: true } as const, { label: 'Delete package…', icon: Trash2, danger: true, onSelect: () => remove(p) }] : [])
			]}
		>
			{#snippet subtitle()}
				<Badge tone={p.client_id ? 'neutral' : 'accent'}>{p.client_name ?? 'Every client'}</Badge>
				{#each sourcesOf(p) as s (s)}<Badge>{s}</Badge>{/each}
				<span>{p.version ? `pinned to ${p.version}` : 'latest version'}</span>
				{#if p.policies}<span>{plural(p.policies, 'policy', 'policies')} require it</span>{/if}
			{/snippet}
		</PageHeader>

		<div class="mb-4 grid gap-4 lg:grid-cols-3">
			<section class="card p-4" aria-label="Where it comes from">
				<h2 class="panel-title mb-2">Where it comes from</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
					{#each [['winget', p.winget_id], ['Chocolatey', p.choco_id], ['apt', p.apt_name], ['dnf', p.dnf_name]] as [label, v] (label)}
						{#if v}<dt class="text-muted">{label}</dt><dd class="font-mono text-[13px]">{v}</dd>{/if}
					{/each}
				</dl>
				{#if !p.winget_id && !p.choco_id && !p.apt_name && !p.dnf_name && !p.installer}<p class="text-muted text-sm">Nothing yet. Add a package id (Edit) or upload an installer.</p>{/if}
			</section>
			<section class="card p-4 lg:col-span-2" aria-label="Uploaded installer">
				<div class="mb-2 flex items-start justify-between gap-2">
					<h2 class="panel-title">Uploaded installer</h2>
					{#if can('technician')}
						<span class="flex gap-2">
							<input bind:this={fileInput} type="file" accept=".msi,.exe" class="sr-only" id="installer-file" onchange={upload} aria-label="Choose an MSI or EXE installer" />
							<Button size="sm" icon={Upload} loading={busy} onclick={() => fileInput?.click()}>{p.installer ? 'Replace' : 'Upload MSI or EXE'}</Button>
							{#if p.installer}<Button size="sm" variant="ghost" icon={Trash2} onclick={() => dropInstaller(p)}>Remove</Button>{/if}
						</span>
					{/if}
				</div>
				{#if p.installer}
					<p class="text-sm"><span class="font-medium">{p.installer.name}</span> <span class="text-muted">· {p.installer.kind.toUpperCase()} · {bytes(p.installer.size)}</span></p>
					<p class="text-muted mt-1 font-mono text-xs break-all">SHA-256 {p.installer.sha256}</p>
					<p class="text-muted mt-1 text-xs">Devices download it from this server and check that hash before running it silently{p.silent_args ? ` with “${p.silent_args}”` : ''}.</p>
					{#if p.installer.kind === 'exe' && !p.silent_args}<p class="text-danger mt-1 text-xs" role="alert">An EXE needs silent arguments; edit the package.</p>{/if}
				{:else}
					<p class="text-muted text-sm">For software that isn’t on winget or Chocolatey: upload the MSI or EXE once, and deploy it to Windows devices. It’s limited by the attachment size limit.</p>
				{/if}
			</section>
		</div>

		{#snippet hostCell(d: SoftwareDevice)}
			<span class="inline-flex items-center gap-1.5"><OsIcon os={d.os_family} class="size-4" /><a class="hover:text-accent font-medium" href="/agents/{d.agent_id}?tab=deployments">{d.hostname}</a></span>
			<div class="text-muted text-xs">{d.client_name} › {d.site_name}</div>
		{/snippet}
		{#snippet versionCell(d: SoftwareDevice)}
			{#if d.installed}<span class="font-mono text-xs">{d.installed}</span>{#if d.available}<span class="text-warning ml-1 text-xs" title="A newer version is on offer">→ {d.available}</span>{/if}{:else}<span class="text-muted">{d.checked_at ? 'Not installed' : 'Not scanned'}</span>{/if}
		{/snippet}
		{#snippet wantCell(d: SoftwareDevice)}{#if d.desired}{wantLabels[d.desired]}{:else}<span class="text-muted">No policy</span>{/if}{/snippet}
		{#snippet stateCell(d: SoftwareDevice)}
			{@const s = standing(d)}
			{#if s}<Badge tone={s.tone} title={s.title}>{s.label}</Badge>{:else}<span class="text-muted" aria-label="none">–</span>{/if}
			{#if d.last_run?.status === 'failed' && d.last_run.error}<div class="text-danger mt-0.5 max-w-xs truncate text-xs" title={d.last_run.error}>{d.last_run.error}</div>{/if}
		{/snippet}
		{#snippet viaCell(d: SoftwareDevice)}<span class="text-muted">{d.provider ? (providerLabels[d.provider] ?? d.provider) : '–'}</span>{/snippet}
		{#snippet onlineCell(d: SoftwareDevice)}<Status online={d.online} />{/snippet}
		<DataTable
			id="software-devices"
			caption="Devices"
			{rows}
			key={(d) => d.agent_id}
			loading={devices.loading}
			busy={devices.busy}
			bind:selected
			columns={[
				{ id: 'host', label: 'Device', cell: hostCell, hideable: false },
				{ id: 'version', label: 'Version', cell: versionCell },
				{ id: 'want', label: 'Policy asks', cell: wantCell, from: 'md' },
				{ id: 'state', label: 'State', cell: stateCell },
				{ id: 'via', label: 'Found by', cell: viaCell, from: 'xl' },
				{ id: 'online', label: 'Status', cell: onlineCell, from: 'lg' }
			] satisfies Column<SoftwareDevice>[]}
		>
			{#snippet toolbar()}
				<Segmented label="Show" value={show} onchange={(v) => setParams({ show: v === 'installed' ? null : v })} options={[{ value: 'installed', label: 'Installed or required' }, { value: 'noncompliant', label: 'Not compliant' }, { value: 'all', label: 'Every device' }]} />
				<Input icon={Search} data-search placeholder="Device…" aria-label="Search devices" class="min-w-0 flex-1 sm:w-56 sm:flex-none" bind:value={q} />
				<span class="text-muted text-xs">{num(p.installed_on)} installed</span>
				{#if can('technician')}<Button size="sm" variant="ghost" icon={RefreshCw} class="sm:ml-auto" onclick={scan}>Rescan</Button>{/if}
			{/snippet}
			{#snippet bulk()}
				{#if can('technician')}
					<Button size="sm" variant="primary" icon={Download} onclick={() => (deploy = { op: 'install' })}>Install</Button>
					<Button size="sm" onclick={() => (deploy = { op: 'upgrade' })}>Upgrade</Button>
					<Button size="sm" variant="danger" onclick={() => (deploy = { op: 'uninstall' })}>Uninstall</Button>
				{/if}
			{/snippet}
			{#snippet empty()}
				<EmptyState compact title={show === 'all' ? 'No device can use this package' : 'Not installed or required anywhere yet'} description={show === 'all' ? 'It needs a package id or installer for the devices’ OS.' : 'Choose “Every device” to install it on some, or require it in a policy set.'} />
			{/snippet}
		</DataTable>

		{#if editing}
			<Modal title="Edit {p.name}" size="lg" onclose={() => (editing = false)}>
				<PackageForm pkg={p} oncancel={() => (editing = false)} ondone={(r) => ((editing = false), pkg.set(r))} />
			</Modal>
		{/if}
		{#if deploy}
			<Modal
				title="{opLabels[deploy.op]} {p.name}?"
				description="On {plural(picked.length, 'device')}. Offline devices run it when they reconnect."
				size="sm"
				onclose={() => (deploy = null)}
			>
				{#if p.choco_id && !p.winget_id}
					<Checkbox bind:checked={bootstrap}>Install Chocolatey first on devices that don’t have it</Checkbox>
					<p class="text-muted mt-1 text-xs">That downloads and runs Chocolatey’s install script from chocolatey.org.</p>
				{/if}
				{#if deploy.op === 'uninstall'}<p class="text-sm">It is removed from every chosen device. A policy that requires it installs it again.</p>{:else if deploy.op === 'upgrade'}<p class="text-sm">Brings installed copies to {p.version ? `the pinned version ${p.version}` : 'the newest version'}.</p>{/if}
				{#snippet footer()}
					<Button variant="ghost" onclick={() => (deploy = null)}>Cancel</Button>
					<Button variant={deploy?.op === 'uninstall' ? 'danger' : 'primary'} loading={busy} onclick={run}>{deploy ? opLabels[deploy.op] : ''}</Button>
				{/snippet}
			</Modal>
		{/if}
	{/snippet}
</Async>
