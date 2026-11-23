<script lang="ts">
	import { FlaskConical, ListTree, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients } from '#lib/scope.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import ClientAccess from '#lib/components/ClientAccess.svelte';

	type Preset = 'entra' | 'google' | 'custom';
	interface MapRow { group_value: string; role: string; extra_permissions: string[]; all_clients: boolean; client_ids: string[] }
	interface Provider {
		id: string; name: string; preset: Preset; issuer: string; client_id: string; has_secret: boolean; scopes: string; enabled: boolean;
		groups_claim: string; jit: boolean; group_sync: boolean; default_role: string | null; allowed_domains: string[]; allowed_tenants: string[];
		trust_email: boolean; identities: number; maps: MapRow[];
	}
	interface Settings { providers: Provider[]; redirect_uri: string; sso_required: boolean; break_glass: { id: string; email: string; name: string }[] }

	const res = resource(() => api.get<Settings>('/settings/sso'));

	const presets = { entra: 'Microsoft Entra ID', google: 'Google', custom: 'Other OpenID Connect' } as const;
	const roles = [
		{ value: 'admin', label: 'Admin' },
		{ value: 'technician', label: 'Technician' },
		{ value: 'readonly', label: 'Read-only' }
	];
	const perms = [
		{ value: 'security.read', label: 'See protection' },
		{ value: 'security.respond', label: 'Respond' },
		{ value: 'security.manage', label: 'Manage security' },
		{ value: 'billing.read', label: 'See billing' },
		{ value: 'billing.manage', label: 'Manage billing' },
		{ value: 'time.approve', label: 'Approve time' },
		{ value: 'vault.read', label: 'See passwords' },
		{ value: 'vault.manage', label: 'Manage passwords' },
		{ value: 'audit.read', label: 'Audit log' }
	];

	// --- requiring SSO ---------------------------------------------------------------------------------------------
	async function setRequired(on: boolean) {
		if (!(await attempt(() => api.put('/settings/sso', { required: on }), on ? 'Single sign-on is now required.' : 'Passwords work again for everyone.'))) {
			// The server refused (no break-glass admin, say): the switch goes back.
		}
		res.reload();
	}

	// --- provider form -------------------------------------------------------------------------------------------------
	const entraIssuer = (tenant: string) => `https://login.microsoftonline.com/${tenant.trim()}/v2.0`;
	const blank = () => ({
		id: '' as string, name: '', preset: 'entra' as Preset, tenant: '', issuer: '', client_id: '', client_secret: '', scopes: 'openid email profile',
		groups_claim: 'groups', enabled: true, jit: false, group_sync: false, default_role: '', allowed_domains: '', allowed_tenants: '', trust_email: false,
		has_secret: false
	});
	let form = $state<ReturnType<typeof blank> | null>(null);
	let busy = $state(false);
	let formError = $state('');

	function edit(p: Provider | null) {
		formError = '';
		if (!p) {
			form = blank();
			return;
		}
		const tenant = p.preset === 'entra' ? (p.issuer.match(/microsoftonline\.com\/([^/]+)\/v2\.0$/)?.[1] ?? '') : '';
		form = {
			id: p.id, name: p.name, preset: p.preset, tenant, issuer: p.issuer, client_id: p.client_id, client_secret: '', scopes: p.scopes,
			groups_claim: p.groups_claim, enabled: p.enabled, jit: p.jit, group_sync: p.group_sync, default_role: p.default_role ?? '',
			allowed_domains: p.allowed_domains.join(', '), allowed_tenants: p.allowed_tenants.join(', '), trust_email: p.trust_email, has_secret: p.has_secret
		};
	}

	const list = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
	const multiTenant = $derived(form?.preset === 'entra' && ['organizations', 'common'].includes(form.tenant.trim()));

	async function save(e: SubmitEvent) {
		e.preventDefault();
		const f = form!;
		busy = true;
		formError = '';
		const body = {
			name: f.name, preset: f.preset,
			issuer: f.preset === 'entra' ? entraIssuer(f.tenant) : f.preset === 'google' ? 'https://accounts.google.com' : f.issuer,
			client_id: f.client_id, client_secret: f.client_secret || undefined, scopes: f.scopes, groups_claim: f.groups_claim, enabled: f.enabled,
			jit: f.jit, group_sync: f.group_sync, default_role: f.default_role || null, allowed_domains: list(f.allowed_domains),
			allowed_tenants: f.preset === 'entra' ? list(f.allowed_tenants) : [], trust_email: f.preset === 'custom' && f.trust_email
		};
		try {
			if (f.id) await api.put(`/settings/sso/providers/${f.id}`, body);
			else await api.post('/settings/sso/providers', body);
			toast.success(f.id ? 'Provider saved.' : 'Provider added. Add group mappings next.');
			form = null;
			res.reload();
		} catch (err) {
			formError = (err as Error).message;
		} finally {
			busy = false;
		}
	}

	async function remove(p: Provider) {
		const ok = await confirmAction({
			title: `Remove ${p.name}?`,
			message: `Its ${p.identities} linked sign-in${p.identities === 1 ? '' : 's'} and group mappings go too, and everyone signed in through it is signed out. Accounts stay; they can use a password if they have one.`,
			confirmLabel: 'Remove',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/settings/sso/providers/${p.id}`), `${p.name} removed.`))) res.reload();
	}

	async function test(p: Provider) {
		try {
			const r = await api.post<{ ok: boolean; error?: string; keys?: number; issuer?: string }>(`/settings/sso/providers/${p.id}/test`);
			if (r.ok) toast.success(`${p.name} answers: ${r.keys} signing key${r.keys === 1 ? '' : 's'} found.`);
			else toast.error(new Error(r.error ?? 'The provider did not answer'));
		} catch (err) {
			toast.error(err);
		}
	}

	// --- group mappings ----------------------------------------------------------------------------------------------------
	let mapping = $state<{ provider: Provider; rows: MapRow[] } | null>(null);
	function openMaps(p: Provider) {
		mapping = { provider: p, rows: p.maps.map((m) => ({ ...m, extra_permissions: [...m.extra_permissions], client_ids: [...m.client_ids] })) };
	}
	const addRow = () => mapping?.rows.push({ group_value: '', role: 'technician', extra_permissions: [], all_clients: false, client_ids: [] });
	async function saveMaps(e: SubmitEvent) {
		e.preventDefault();
		const m = mapping!;
		if (await attempt(() => api.put(`/settings/sso/providers/${m.provider.id}/maps`, m.rows.filter((r) => r.group_value.trim())), 'Group mappings saved.')) {
			mapping = null;
			res.reload();
		}
	}
	function togglePerm(r: MapRow, perm: string, on: boolean) {
		r.extra_permissions = on ? [...r.extra_permissions, perm] : r.extra_permissions.filter((p) => p !== perm);
	}
</script>

<Async {res}>
	{#snippet children(data)}
		<div class="max-w-5xl space-y-5">
			<section class="card space-y-4 p-5">
				<div>
					<h2 class="font-semibold">Single sign-on</h2>
					<p class="text-muted mt-0.5 text-sm">
						Technicians sign in with your identity provider (OpenID Connect). It does the second factor, so SSO sessions don’t ask for an authenticator code here.
						Register this redirect URL with the provider:
					</p>
				</div>
				<div class="flex items-center gap-2">
					<code class="code-block block min-w-0 flex-1 truncate text-sm select-all">{data.redirect_uri}</code>
					<CopyButton text={data.redirect_uri} label="Copy redirect URL" />
				</div>
				<div class="border-border border-t pt-4">
					<Switch checked={data.sso_required} onchange={setRequired}>
						<span class="font-medium">Require single sign-on</span>
						<span class="text-muted mt-0.5 block text-xs">Passwords stop working for everyone except break-glass accounts. Mark an admin as one with “Allow password sign-in” on the Users page first.</span>
					</Switch>
					{#if data.break_glass.length > 0}
						<p class="text-muted mt-3 text-xs">Break-glass accounts: {data.break_glass.map((u) => u.email).join(', ')}</p>
					{:else}
						<p class="text-warning mt-3 text-xs">No break-glass admin yet. Without one, SSO can’t be required (you’d be locked out if the provider failed).</p>
					{/if}
				</div>
			</section>

			<section>
				<div class="mb-3 flex items-center justify-between gap-3">
					<h2 class="font-semibold">Identity providers</h2>
					<Button variant="primary" icon={Plus} onclick={() => edit(null)}>Add provider</Button>
				</div>
				{#snippet nameCell(p: Provider)}
					<div class="font-medium">{p.name}</div>
					<div class="text-muted max-w-xs truncate text-xs" title={p.issuer}>{presets[p.preset]} · {p.issuer}</div>
				{/snippet}
				{#snippet accessCell(p: Provider)}
					<div class="text-xs">
						{p.group_sync ? `${p.maps.length} group mapping${p.maps.length === 1 ? '' : 's'}` : 'Access set by admins'}
						{#if p.jit}<div class="text-muted">Creates accounts at first sign-in</div>{/if}
					</div>
				{/snippet}
				{#snippet statusCell(p: Provider)}
					{#if p.enabled}<Badge tone="success">On</Badge>{:else}<Badge>Off</Badge>{/if}
					<span class="text-muted ml-2 text-xs">{p.identities} linked</span>
				{/snippet}
				{#snippet actionsCell(p: Provider)}
					<div class="flex justify-end gap-0.5">
						<IconButton icon={ListTree} label="Group mappings for {p.name}" size="sm" onclick={() => openMaps(p)} />
						<IconButton icon={FlaskConical} label="Test {p.name}" size="sm" onclick={() => test(p)} />
						<IconButton icon={Pencil} label="Edit {p.name}" size="sm" onclick={() => edit(p)} />
						<IconButton icon={Trash2} label="Remove {p.name}" size="sm" onclick={() => remove(p)} />
					</div>
				{/snippet}
				<DataTable
					id="sso-providers"
					caption="Identity providers"
					rows={data.providers}
					key={(p) => p.id}
					scroll={false}
					columns={[
						{ id: 'name', label: 'Provider', cell: nameCell, hideable: false },
						{ id: 'access', label: 'Access', cell: accessCell, from: 'md' },
						{ id: 'status', label: 'Status', cell: statusCell },
						{ id: 'actions', label: '', cell: actionsCell, hideable: false, align: 'right', class: 'w-40' }
					] satisfies Column<Provider>[]}
				/>
				{#if data.providers.length === 0}
					<p class="text-muted mt-3 text-sm">No provider yet. Entra ID and Google work out of the box; any OpenID Connect provider will do.</p>
				{/if}
			</section>
		</div>
	{/snippet}
</Async>

{#if form}
	<Modal title={form.id ? 'Edit provider' : 'Add provider'} size="lg" onclose={() => (form = null)}>
		<form id="sso-form" class="space-y-4" onsubmit={save}>
			<div>
				<div class="label">Provider</div>
				<Segmented
					label="Provider type"
					size="md"
					value={form.preset}
					onchange={(v: Preset) => form && (form.preset = v)}
					options={(Object.keys(presets) as Preset[]).map((k) => ({ value: k, label: presets[k] }))}
				/>
			</div>
			<div class="grid gap-4 sm:grid-cols-2">
				<Field label="Button label" id="sn" hint="Shown on the sign-in page: “Sign in with …”." required><Input id="sn" required maxlength={60} placeholder={presets[form.preset]} bind:value={form.name} /></Field>
				{#if form.preset === 'entra'}
					<Field label="Tenant" id="st" hint="The tenant (directory) ID, or “organizations” to admit several tenants." required>
						<Input id="st" required placeholder="00000000-0000-0000-0000-000000000000" bind:value={form.tenant} />
					</Field>
				{:else if form.preset === 'custom'}
					<Field label="Issuer URL" id="si" hint="The address that serves /.well-known/openid-configuration." required>
						<Input id="si" type="url" required placeholder="https://idp.example.com/realms/msp" bind:value={form.issuer} />
					</Field>
				{/if}
				<Field label="Client ID" id="sc" required><Input id="sc" required autocomplete="off" bind:value={form.client_id} /></Field>
				<Field label="Client secret" id="ss" hint={form.has_secret ? 'Leave empty to keep the current secret.' : 'Stored encrypted with RMM_DATA_KEY.'} required={!form.has_secret}>
					<Input id="ss" type="password" autocomplete="new-password" required={!form.has_secret} placeholder={form.has_secret ? '••••••••' : ''} bind:value={form.client_secret} />
				</Field>
			</div>
			{#if form.preset === 'entra' && multiTenant}
				<Field label="Allowed tenants" id="sat" hint="Tenant IDs, separated by commas. A multi-tenant endpoint admits every Microsoft tenant, so name the ones whose users may sign in." required>
					<Input id="sat" required placeholder="11111111-2222-3333-4444-555555555555" bind:value={form.allowed_tenants} />
				</Field>
			{/if}
			<Field label="Allowed email domains" id="sd" hint="Only these may sign in, e.g. msp.example. Empty means any address the provider vouches for.">
				<Input id="sd" placeholder="msp.example" bind:value={form.allowed_domains} />
			</Field>

			<fieldset class="border-border space-y-3 rounded-md border p-4">
				<legend class="px-1 text-sm font-semibold">Accounts and access</legend>
				<Switch bind:checked={form.group_sync}>
					<span>Role and clients follow IdP groups</span>
					<span class="text-muted mt-0.5 block text-xs">Applied at every sign-in from the group mappings. Break-glass accounts are never changed.</span>
				</Switch>
				<Switch bind:checked={form.jit}>
					<span>Create accounts at first sign-in</span>
					<span class="text-muted mt-0.5 block text-xs">Otherwise only people who already have an account (matched by a verified email address) can sign in.</span>
				</Switch>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field label="Role for people no group matches" id="sr" hint="“Nobody” refuses them (with group mappings) or doesn’t create them.">
						<Select id="sr" bind:value={form.default_role} options={[{ value: '', label: 'Nobody' }, ...roles]} />
					</Field>
					{#if form.preset !== 'google'}
						<Field label="Groups claim" id="sg" hint="The ID token claim listing groups. Entra: groups (object IDs)."><Input id="sg" bind:value={form.groups_claim} /></Field>
					{/if}
				</div>
				{#if form.preset === 'custom'}
					<Switch bind:checked={form.trust_email}>
						<span>Trust the email address</span>
						<span class="text-muted mt-0.5 block text-xs">For providers that don’t send <code>email_verified</code> but only issue verified addresses. Never enable it for a provider anyone can register an address with.</span>
					</Switch>
				{/if}
				{#if form.preset === 'google'}
					<p class="text-muted text-xs">Google doesn’t send groups: use “Role for people no group matches” and set clients on the Users page, or use Entra or another provider for group mappings.</p>
				{/if}
			</fieldset>
			<Switch bind:checked={form.enabled}>Enabled</Switch>
			{#if formError}<p class="bg-danger-soft text-danger rounded-md px-3 py-2 text-sm" role="alert">{formError}</p>{/if}
		</form>
		{#snippet footer()}
			<Button onclick={() => (form = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="sso-form" loading={busy}>{form?.id ? 'Save' : 'Add provider'}</Button>
		{/snippet}
	</Modal>
{/if}

{#if mapping}
	<Modal title="Group mappings" description={mapping.provider.name} size="lg" onclose={() => (mapping = null)}>
		<form id="sso-maps" class="space-y-4" onsubmit={saveMaps}>
			{#if !mapping.provider.group_sync}
				<p class="border-warning/40 bg-warning-soft text-warning rounded-md border px-3 py-2 text-sm" role="status">
					“Role and clients follow IdP groups” is off for this provider, so these mappings are ignored. Turn it on in the provider settings.
				</p>
			{/if}
			<p class="text-muted text-sm">
				A person in several groups gets the highest role, every client of those groups and every extra permission. Group values are compared without regard to case; Entra sends group object IDs.
			</p>
			{#each mapping.rows as r, i (i)}
				<div class="border-border space-y-3 rounded-md border p-3">
					<div class="grid items-end gap-3 sm:grid-cols-[1fr_12rem_auto]">
						<Field label="Group" id="mg{i}"><Input id="mg{i}" placeholder="msp-technicians" bind:value={r.group_value} /></Field>
						<Field label="Role" id="mr{i}"><Select id="mr{i}" bind:value={r.role} options={roles} /></Field>
						<IconButton icon={Trash2} label="Remove mapping {i + 1}" onclick={() => mapping?.rows.splice(i, 1)} />
					</div>
					{#if r.role !== 'admin'}
						<details>
							<summary class="text-muted cursor-pointer text-sm">Clients and extra permissions</summary>
							<div class="mt-3 grid gap-4 md:grid-cols-2">
								<div><div class="label">Clients</div><ClientAccess clients={clients.list} bind:value={mapping.rows[i]} /></div>
								<div>
									<div class="label">Extra permissions</div>
									<div class="space-y-1.5">
										{#each perms as p (p.value)}
											<div><Checkbox checked={r.extra_permissions.includes(p.value)} onchange={(on) => togglePerm(r, p.value, on)}>{p.label}</Checkbox></div>
										{/each}
									</div>
								</div>
							</div>
						</details>
					{/if}
				</div>
			{/each}
			<Button icon={Plus} onclick={addRow}>Add mapping</Button>
		</form>
		{#snippet footer()}
			<Button onclick={() => (mapping = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="sso-maps">Save</Button>
		{/snippet}
	</Modal>
{/if}
