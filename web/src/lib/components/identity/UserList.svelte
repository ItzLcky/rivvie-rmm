<script lang="ts">
	import { Pencil, Plus, RefreshCw, Search, ShieldAlert, Trash2, UserRound, Waypoints } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { kindLabel, userFilters, type DirUser, type IdentitySource } from '#lib/identity.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed, can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Select from '#lib/ui/Select.svelte';
	import SourceForm from './SourceForm.svelte';
	import UserDrawer from './UserDrawer.svelte';

	/** The client's directories and their users: the "Users" tab. */
	let { clientId, clientName }: { clientId: string; clientName: string } = $props();

	const sources = resource(() => api.get<IdentitySource[]>(`/clients/${clientId}/identity-sources`));
	const sort = sortState('name');
	let q = $state(param('iq'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ iq: v.trim() || null, after: null, before: null }), 250);
		return () => clearTimeout(t);
	});
	const users = paged<DirUser>(() => `/clients/${clientId}/identity/users${qs({ filter: param('idf'), source_id: param('isrc'), q: param('iq'), sort: sort.key, dir: sort.dir })}`);
	let editing = $state<IdentitySource | 'new' | null>(null);
	let open = $state<string | null>(param('iu') || null);
	let syncing = $state<string | null>(null);

	async function sync(s: IdentitySource) {
		syncing = s.id;
		try {
			const r = await api.post<{ stats: { users: number; groups: number; devices: number | null; devices_error?: string } }>(`/identity-sources/${s.id}/sync`);
			toast.success(`${s.name}: ${plural(r.stats.users, 'user')} and ${plural(r.stats.groups, 'group')}${r.stats.devices != null ? `, ${plural(r.stats.devices, 'device')}` : ''}.`);
		} catch (e) {
			toast.error(e);
		} finally {
			syncing = null;
			sources.reload();
			users.reload();
		}
	}
	async function test(s: IdentitySource) {
		type Tested = { ok: boolean; detail?: string; error?: string };
		const r = await api.post<Tested>(`/identity-sources/${s.id}/test`).catch((e): Tested => ({ ok: false, error: String(e.message ?? e) }));
		if (r.ok) toast.success(`${s.name}: ${r.detail}.`);
		else toast.error(`${s.name}: ${r.error}`);
	}
	async function remove(s: IdentitySource) {
		if (await confirmAction({ title: `Remove ${s.name}?`, message: 'Its synced users, groups and devices are removed here; nothing changes in the directory.', confirmLabel: 'Remove', danger: true })) {
			if (await attempt(() => api.del(`/identity-sources/${s.id}`), `${s.name} removed.`)) {
				sources.reload();
				users.reload();
			}
		}
	}
	function show(id: string | null) {
		open = id;
		setParams({ iu: id });
	}
	const filtered = $derived(!!(param('iq') || param('idf') || param('isrc')));
</script>

<div class="space-y-4">
	<section class="card" aria-labelledby="dirs-h">
		<header class="panel-head">
			<div class="min-w-0">
				<h2 id="dirs-h" class="font-semibold">Directories</h2>
				<p class="text-muted text-xs">Where {clientName}’s accounts live. Synced on a schedule; changes made here go straight to the directory.</p>
			</div>
			{#if can('admin')}<Button size="sm" variant="primary" icon={Plus} onclick={() => (editing = 'new')}>Add directory</Button>{/if}
		</header>
		<Async res={sources} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as s (s.id)}
							<li class="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
								<div class="min-w-0 flex-1">
									<div class="flex flex-wrap items-center gap-1.5 font-medium">
										{s.name}
										<Badge tone="info">{kindLabel[s.kind]}</Badge>
										{#if s.sync_devices}<Badge>Intune</Badge>{/if}
										{#if !s.enabled}<Badge>Paused</Badge>{/if}
									</div>
									<div class="text-muted text-xs">
										{s.kind === 'ad' ? `via ${s.agent_hostname ?? 'no agent'}${s.agent_online === false ? ' (offline)' : ''}` : s.tenant_id}
										· {plural(s.users, 'user')} · {plural(s.groups, 'group')}{s.sync_devices ? ` · ${plural(s.devices, 'device')}` : ''}
										· <span title={datetime(s.last_sync_at)}>{s.last_sync_at ? `synced ${ago(s.last_sync_at)}` : 'never synced'}</span>
									</div>
									{#if s.last_error}<div class="text-danger mt-0.5 text-xs">{s.last_error}</div>{/if}
								</div>
								{#if allowed('identity.manage')}<Button size="sm" icon={RefreshCw} loading={syncing === s.id} onclick={() => sync(s)}>Sync now</Button>{/if}
								{#if can('admin')}
									<IconButton icon={Waypoints} size="sm" label="Test the connection to {s.name}" onclick={() => test(s)} />
									<IconButton icon={Pencil} size="sm" label="Edit {s.name}" onclick={() => (editing = s)} />
									<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Remove {s.name}" onclick={() => remove(s)} />
								{/if}
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={UserRound} title="No directory yet" description={can('admin') ? 'Add the client’s Entra ID tenant or its Active Directory to manage their accounts from here.' : 'An admin can add the client’s Entra ID tenant or Active Directory.'} />
				{/if}
			{/snippet}
		</Async>
	</section>

	{#if sources.data?.length}
		{#snippet nameCell(u: DirUser)}
			<button class="hover:text-accent text-left font-medium" onclick={() => show(u.id)}>{u.display_name || u.username}</button>
			<div class="text-muted text-xs">{u.upn || u.username}</div>
		{/snippet}
		{#snippet stateCell(u: DirUser)}
			<div class="flex flex-wrap gap-1">
				{#if u.deleted_at}<Badge>Gone</Badge>{:else if !u.enabled}<Badge>Disabled</Badge>{:else}<Badge tone="success">Enabled</Badge>{/if}
				{#if u.locked}<Badge tone="danger">Locked</Badge>{/if}
				{#if u.privileged}<Badge tone="warning"><ShieldAlert class="size-3" /> Privileged</Badge>{/if}
				{#if u.mfa_registered === false}<Badge tone="warning">No MFA</Badge>{/if}
				{#if u.synced_from_ad}<Badge tone="info">From AD</Badge>{/if}
			</div>
		{/snippet}
		{#snippet logonCell(u: DirUser)}<span class="text-muted whitespace-nowrap" title={datetime(u.last_logon_at)}>{u.last_logon_at ? ago(u.last_logon_at) : '–'}</span>{/snippet}
		{#snippet pwCell(u: DirUser)}<span class="text-muted whitespace-nowrap" title={datetime(u.password_last_set)}>{u.password_last_set ? ago(u.password_last_set) : '–'}</span>{/snippet}
		{#snippet sourceCell(u: DirUser)}<span class="text-muted whitespace-nowrap">{u.source_name}</span>{/snippet}
		{#snippet contactCell(u: DirUser)}<span class="text-muted">{u.contact_name ?? '–'}</span>{/snippet}
		<DataTable
			id="identity-users"
			caption="{clientName}’s directory users"
			rows={users.rows}
			key={(u) => u.id}
			loading={users.loading && !users.data}
			busy={users.busy}
			{sort}
			activeFilters={[param('idf'), param('isrc')].filter(Boolean).length}
			columns={[
				{ id: 'name', label: 'Name', sort: 'name', cell: nameCell, hideable: false },
				{ id: 'state', label: 'State', cell: stateCell },
				{ id: 'logon', label: 'Last sign-in', sort: 'last_logon', cell: logonCell, from: 'md' },
				{ id: 'pw', label: 'Password set', sort: 'password_last_set', cell: pwCell, from: 'lg' },
				{ id: 'contact', label: 'Contact', cell: contactCell, from: 'xl' },
				{ id: 'source', label: 'Directory', cell: sourceCell, from: 'lg' }
			] satisfies Column<DirUser>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="Name, user name or email…" aria-label="Search users" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
			{/snippet}
			{#snippet filters()}
				<Select aria-label="Show" class="w-full sm:w-auto" value={param('idf')} onchange={(e) => setParams({ idf: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Every account' }, ...userFilters]} />
				{#if (sources.data?.length ?? 0) > 1}
					<Select aria-label="Directory" class="w-full sm:w-auto" value={param('isrc')} onchange={(e) => setParams({ isrc: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Every directory' }, ...(sources.data ?? []).map((s) => ({ value: s.id, label: s.name }))]} />
				{/if}
			{/snippet}
			{#snippet empty()}
				{#if filtered}
					<EmptyState title="No accounts match" description="Try other filters.">
						{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ iq: null, idf: null, isrc: null }); }}>Clear filters</Button>{/snippet}
					</EmptyState>
				{:else}
					<EmptyState icon={UserRound} title="No accounts synced yet" description="Sync a directory to read its users." />
				{/if}
			{/snippet}
			{#snippet footer()}
				{#if users.data && (users.data.next || users.data.prev)}
					<Pagination shown={users.rows.length} total={users.data.total} hasPrev={!!users.data.prev} hasNext={!!users.data.next} pageSize={users.pageSize} onprev={users.prev} onnext={users.next} onfirst={users.first} onpagesize={users.setPageSize} />
				{/if}
			{/snippet}
		</DataTable>
	{/if}
</div>

{#if editing}
	<SourceForm {clientId} source={editing === 'new' ? null : editing} onclose={() => (editing = null)} ondone={() => ((editing = null), sources.reload())} />
{/if}
{#if open}
	<UserDrawer id={open} onclose={() => show(null)} onchange={() => users.reload()} />
{/if}
