<script lang="ts">
	import { Building2, KeyRound, ShieldCheck, MonitorSmartphone, ShieldOff, UserCheck, UserPlus, UserX } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients } from '#lib/scope.svelte.js';
	import { session } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import ClientAccess from '#lib/components/ClientAccess.svelte';
	import Sessions from '#lib/components/Sessions.svelte';

	interface UserRow {
		id: string; email: string; name: string; role: string; disabled: boolean; totp_enabled: boolean; last_login_at: string | null;
		all_clients: boolean; client_ids: string[];
		/** null = the role's defaults */
		permissions?: string[] | null;
	}
	const res = resource(() => api.get<UserRow[]>('/users'));

	function access(u: UserRow): string {
		if (u.role === 'admin' || u.all_clients) return 'All clients';
		const names = clients.list.filter((c) => u.client_ids.includes(c.id)).map((c) => c.name);
		return names.length === 0 ? 'None' : names.length <= 2 ? names.join(', ') : `${names.length} clients`;
	}

	const blank = () => ({ email: '', name: '', password: '', role: 'technician', all_clients: true, client_ids: [] as string[] });
	let adding = $state(false);
	let form = $state(blank());
	let busy = $state(false);
	async function add(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		const ok = await attempt(() => api.post('/users', form), `${form.email} added.`);
		busy = false;
		if (ok) {
			adding = false;
			form = blank();
			res.reload();
		}
	}

	let editingAccess = $state<UserRow | null>(null);
	let accessForm = $state({ all_clients: true, client_ids: [] as string[] });
	async function saveAccess(e: SubmitEvent) {
		e.preventDefault();
		if (await attempt(() => api.put(`/users/${editingAccess!.id}/access`, accessForm), 'Client access saved.')) {
			editingAccess = null;
			res.reload();
		}
	}

	async function disable(u: UserRow) {
		const ok = await confirmAction({ title: `Disable ${u.email}?`, message: 'They are signed out everywhere and can’t sign in until re-enabled.', confirmLabel: 'Disable', danger: true });
		if (ok && (await attempt(() => api.del(`/users/${u.id}`), `${u.email} disabled.`))) res.reload();
	}
	async function enable(u: UserRow) {
		if (await attempt(() => api.post(`/users/${u.id}/enable`), `${u.email} enabled.`)) res.reload();
	}

	let resetting = $state<UserRow | null>(null);
	let resetPw = $state('');
	async function reset(e: SubmitEvent) {
		e.preventDefault();
		if (await attempt(() => api.post(`/users/${resetting!.id}/password`, { password: resetPw }), 'Password reset; they were signed out everywhere.')) {
			resetting = null;
			resetPw = '';
		}
	}

	let viewing = $state<UserRow | null>(null);

	async function reset2fa(u: UserRow) {
		const ok = await confirmAction({
			title: `Reset 2FA for ${u.email}?`,
			message: 'Removes their authenticator and recovery codes and signs them out everywhere. Do this when they’ve lost their phone, after confirming it’s really them. If 2FA is required for them, they set it up again at their next sign-in.',
			confirmLabel: 'Reset 2FA',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/users/${u.id}/totp`), '2FA reset.'))) res.reload();
	}

	const roles: Record<string, string> = { admin: 'Admin', technician: 'Technician', readonly: 'Read-only' };

	// Named permissions (security, billing, time approval): the role's defaults, or an explicit set.
	const perms = [
		{ value: 'security.read', label: 'See protection', hint: 'Protection state, detections, quarantine and telemetry' },
		{ value: 'security.respond', label: 'Respond', hint: 'Scans, kill, quarantine and restore, isolate, triage, verdicts' },
		{ value: 'security.manage', label: 'Manage', hint: 'Security policies, exclusions, rule modes and content rollout' },
		{ value: 'billing.read', label: 'See billing', hint: 'Rates, contracts, invoices and money in reports' },
		{ value: 'billing.manage', label: 'Manage billing', hint: 'Contracts, products, rates, invoice runs and accounting' },
		{ value: 'time.approve', label: 'Approve time', hint: 'Approve and reject timesheets' }
	];
	const roleDefaults: Record<string, string[]> = {
		admin: ['security.read', 'security.respond', 'security.manage', 'billing.read', 'billing.manage', 'time.approve'],
		technician: ['security.read', 'security.respond'],
		readonly: ['security.read']
	};
	const permLabel = (list: string[]) => (list.length ? perms.filter((p) => list.includes(p.value)).map((p) => p.label).join(', ') : 'No access');
	let editingPerms = $state<UserRow | null>(null);
	let permMode = $state<'role' | 'custom'>('role');
	let permSet = $state<string[]>([]);
	function openPerms(u: UserRow) {
		editingPerms = u;
		permMode = u.permissions ? 'custom' : 'role';
		permSet = [...(u.permissions ?? roleDefaults[u.role] ?? [])];
	}
	async function savePerms(e: SubmitEvent) {
		e.preventDefault();
		const body = { permissions: permMode === 'role' ? null : perms.map((p) => p.value).filter((v) => permSet.includes(v)) };
		if (await attempt(() => api.put(`/users/${editingPerms!.id}/permissions`, body), 'Endpoint security permissions saved.')) {
			editingPerms = null;
			res.reload();
		}
	}
</script>

<div class="mb-3 flex items-center justify-between gap-3">
	<p class="text-muted text-sm">People who can sign in to this console.</p>
	<Button variant="primary" icon={UserPlus} onclick={() => (adding = true)}>Add user</Button>
</div>

{#snippet nameCell(u: UserRow)}
	<div class={u.disabled ? 'opacity-60' : ''}>
		<div class="font-medium">{u.name}{#if u.id === session.user?.id}<span class="text-muted font-normal"> (you)</span>{/if}</div>
		<div class="text-muted text-xs">{u.email}</div>
	</div>
{/snippet}
{#snippet roleCell(u: UserRow)}<span class={u.disabled ? 'opacity-60' : ''}>{roles[u.role] ?? u.role}</span>{/snippet}
{#snippet accessCell(u: UserRow)}<span class="text-xs {access(u) === 'None' ? 'text-warning' : 'text-muted'}">{access(u)}</span>{/snippet}
{#snippet securityCell(u: UserRow)}
	{#if u.role === 'admin'}<span class="text-muted text-xs">Everything</span>
	{:else if u.permissions}<span class="text-xs">{permLabel(u.permissions)}</span><div class="text-muted text-xs">Custom</div>
	{:else}<span class="text-muted text-xs">{permLabel(roleDefaults[u.role] ?? [])}</span>{/if}
{/snippet}
{#snippet mfaCell(u: UserRow)}
	{#if u.totp_enabled}<Badge tone="success">On</Badge>{:else if u.role === 'admin'}<Badge tone="warning">Not set up</Badge>{:else}<Badge>Off</Badge>{/if}
{/snippet}
{#snippet statusCell(u: UserRow)}{#if u.disabled}<Badge tone="danger">Disabled</Badge>{:else}<span class="text-muted text-xs">{u.last_login_at ? `Signed in ${ago(u.last_login_at)}` : 'Never signed in'}</span>{/if}{/snippet}
{#snippet actionsCell(u: UserRow)}
	{#if u.id === session.user?.id}
		<Button size="xs" variant="ghost" href="/account">Account</Button>
	{:else if u.disabled}
		<Button size="xs" icon={UserCheck} onclick={() => enable(u)}>Enable</Button>
	{:else}
		<Menu
			label="Actions for {u.email}"
			items={[
				...(u.role !== 'admin'
					? [{ label: 'Client access', icon: Building2, onSelect: () => ((editingAccess = u), (accessForm = { all_clients: u.all_clients, client_ids: [...u.client_ids] })) }]
					: []),
				...(u.role !== 'admin' ? [{ label: 'Endpoint security', icon: ShieldCheck, onSelect: () => openPerms(u) }] : []),
				{ label: 'Sessions', icon: MonitorSmartphone, onSelect: () => (viewing = u) },
				{ label: 'Reset password', icon: KeyRound, onSelect: () => ((resetting = u), (resetPw = '')) },
				...(u.totp_enabled ? [{ label: 'Reset 2FA', icon: ShieldOff, onSelect: () => reset2fa(u) }] : []),
				{ separator: true },
				{ label: 'Disable user', icon: UserX, danger: true, onSelect: () => disable(u) }
			]}
		/>
	{/if}
{/snippet}

<DataTable
	id="users"
	caption="Users"
	rows={res.data ?? []}
	key={(u) => u.id}
	loading={res.loading}
	scroll={false}
	columns={[
		{ id: 'name', label: 'User', cell: nameCell, hideable: false },
		{ id: 'role', label: 'Role', cell: roleCell },
		{ id: 'access', label: 'Clients', cell: accessCell, from: 'md' },
		{ id: 'security', label: 'Endpoint security', cell: securityCell, from: 'lg' },
		{ id: 'mfa', label: '2FA', cell: mfaCell, from: 'sm' },
		{ id: 'status', label: 'Last sign-in', cell: statusCell, from: 'lg' },
		{ id: 'actions', label: '', cell: actionsCell, hideable: false, align: 'right', class: 'w-16' }
	] satisfies Column<UserRow>[]}
/>

{#if adding}
	<Modal title="Add user" onclose={() => (adding = false)}>
		<form id="add-user" class="space-y-3" onsubmit={add}>
			<Field label="Email" id="ue" required><Input id="ue" type="email" required autocomplete="off" bind:value={form.email} /></Field>
			<Field label="Name" id="un" required><Input id="un" required bind:value={form.name} /></Field>
			<Field label="Password" id="up" hint="At least 12 characters. Share it over a separate channel." required>
				<Input id="up" type="password" autocomplete="new-password" minlength={12} required bind:value={form.password} />
			</Field>
			<Field label="Role" id="ur">
				<Select
					id="ur"
					bind:value={form.role}
					options={[
						{ value: 'admin', label: 'Admin: everything, including users and clients' },
						{ value: 'technician', label: 'Technician: scripts, terminal, enrollment' },
						{ value: 'readonly', label: 'Read-only: view only' }
					]}
				/>
			</Field>
			{#if form.role !== 'admin'}
				<div><div class="label">Client access</div><ClientAccess clients={clients.list} bind:value={form} /></div>
			{/if}
		</form>
		{#snippet footer()}
			<Button onclick={() => (adding = false)}>Cancel</Button>
			<Button variant="primary" type="submit" form="add-user" loading={busy}>Create user</Button>
		{/snippet}
	</Modal>
{/if}

{#if editingAccess}
	<Modal title="Client access" description={editingAccess.email} onclose={() => (editingAccess = null)}>
		<form id="access" class="space-y-3" onsubmit={saveAccess}>
			<p class="text-muted text-sm">They only see agents, sites, jobs and client scripts of these clients. MSP-wide scripts stay visible. Takes effect on their next request.</p>
			<ClientAccess clients={clients.list} bind:value={accessForm} />
		</form>
		{#snippet footer()}
			<Button onclick={() => (editingAccess = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="access">Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if editingPerms}
	{@const u = editingPerms}
	<Modal title="Endpoint security" description={u.email} onclose={() => (editingPerms = null)}>
		<form id="perms" class="space-y-4" onsubmit={savePerms}>
			<fieldset class="space-y-2">
				<legend class="sr-only">Permissions from</legend>
				<label class="flex items-start gap-2 text-sm">
					<input type="radio" name="perm-mode" value="role" class="accent-accent mt-0.5" bind:group={permMode} />
					<span>Role defaults <span class="text-muted block text-xs">{roles[u.role] ?? u.role}: {permLabel(roleDefaults[u.role] ?? [])}. Follows the role if it changes.</span></span>
				</label>
				<label class="flex items-start gap-2 text-sm">
					<input type="radio" name="perm-mode" value="custom" class="accent-accent mt-0.5" bind:group={permMode} />
					<span>Custom <span class="text-muted block text-xs">Exactly the permissions ticked below, whatever the role.</span></span>
				</label>
			</fieldset>
			<fieldset class="border-border space-y-2.5 rounded-md border p-3" disabled={permMode === 'role'}>
				<legend class="label px-1">Permissions</legend>
				{#each perms as p (p.value)}
					<div>
						<Checkbox
							disabled={permMode === 'role'}
							checked={(permMode === 'role' ? (roleDefaults[u.role] ?? []) : permSet).includes(p.value)}
							onchange={(on) => (permSet = on ? [...new Set([...permSet, p.value])] : permSet.filter((x) => x !== p.value))}>{p.label}</Checkbox
						>
						<p class="hint pl-6">{p.hint}</p>
					</div>
				{/each}
			</fieldset>
			<p class="text-muted text-xs">Client access still applies: they only see and act on agents of their clients. Takes effect on their next request.</p>
		</form>
		{#snippet footer()}
			<Button onclick={() => (editingPerms = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="perms">Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if resetting}
	<Modal title="Reset password" description={resetting.email} onclose={() => (resetting = null)} size="sm">
		<form id="reset" class="space-y-3" onsubmit={reset}>
			<p class="text-muted text-sm">Sets a new password and signs them out of every session. Share it with them over a separate channel.</p>
			<Field label="New password" id="rp" hint="At least 12 characters." required>
				<Input id="rp" type="password" autocomplete="new-password" minlength={12} required bind:value={resetPw} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (resetting = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="reset">Reset password</Button>
		{/snippet}
	</Modal>
{/if}

{#if viewing}
	<Modal title="Sessions" description={viewing.email} onclose={() => (viewing = null)}>
		<Sessions base="/users/{viewing.id}/sessions" revokeAllLabel="Sign out everywhere" />
	</Modal>
{/if}
