<script lang="ts">
	import { KeyRound, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clients } from '#lib/scope.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/**
	 * API keys. On the account page: the signed-in user's own. With `all` (admins, Company
	 * settings → API): everyone's, and keys can be made for service accounts.
	 */
	let { all = false, accounts = [] }: { all?: boolean; accounts?: { id: string; name: string; disabled: boolean }[] } = $props();

	interface Key {
		id: string; name: string; prefix: string; owner_id: string; owner_name: string; service_account: boolean;
		access: 'read' | 'write'; scopes: string[]; permissions: string[]; client_ids: string[] | null; rate_limit_per_min: number;
		expires_at: string | null; last_used_at: string | null; last_used_ip: string | null; revoked_at: string | null; created_at: string;
		status: 'active' | 'expired' | 'revoked';
	}
	interface Options { groups: { id: string; label: string }[]; permissions: string[]; can_write: boolean; default_rate_limit: number }

	const keys = resource(() => api.get<Key[]>(`/api-keys${all ? '?all=true' : ''}`));

	const permLabels: Record<string, string> = {
		'security.read': 'See protection state and detections',
		'security.respond': 'Respond to detections',
		'security.manage': 'Manage security policies',
		'billing.read': 'See billing',
		'billing.manage': 'Manage billing',
		'time.approve': 'Approve timesheets',
		'vault.read': 'See vault passwords',
		'vault.manage': 'Manage vault passwords',
		'audit.read': 'Read and export the audit log',
		'identity.read': 'See Intune devices'
	};

	const blank = () => ({
		name: '', owner: '', access: 'read' as 'read' | 'write', scopes: [] as string[], permissions: [] as string[],
		limited: false, client_ids: [] as string[], expires: '90' as string, rate: 600
	});
	let creating = $state(false);
	let form = $state(blank());
	let options = $state<Options | null>(null);
	let busy = $state(false);
	let created = $state<{ token: string; name: string } | null>(null);

	async function open() {
		form = blank();
		options = null;
		creating = true;
		await loadOptions();
	}
	async function loadOptions() {
		try {
			const o = await api.get<Options>(`/api-keys/options${form.owner ? `?owner_id=${form.owner}` : ''}`);
			options = o;
			// What the owner doesn't hold can't be chosen.
			form.permissions = form.permissions.filter((p) => o.permissions.includes(p));
			if (!o.can_write) form.access = 'read';
			if (!form.rate) form.rate = o.default_rate_limit;
		} catch (err) {
			toast.error(err);
		}
	}
	const toggle = (list: string[], v: string, on: boolean) => (on ? [...list, v] : list.filter((x) => x !== v));

	async function create(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const r = await api.post<{ token: string; key: Key }>('/api-keys', {
				name: form.name,
				access: form.access,
				scopes: form.scopes,
				permissions: form.permissions,
				client_ids: form.limited ? form.client_ids : null,
				expires_in_days: form.expires === 'never' ? null : Number(form.expires),
				rate_limit_per_min: Number(form.rate),
				owner_id: form.owner || undefined
			});
			creating = false;
			created = { token: r.token, name: r.key.name };
			keys.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}

	async function revoke(k: Key) {
		const ok = await confirmAction({
			title: `Revoke ${k.name}?`,
			message: `Anything using ${k.prefix}… stops working at once. This can’t be undone.`,
			confirmLabel: 'Revoke key',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/api-keys/${k.id}`), `${k.name} revoked.`))) keys.reload();
	}

	const clientNames = (k: Key) =>
		k.client_ids === null ? 'All the owner’s' : k.client_ids.map((id) => clients.list.find((c) => c.id === id)?.name ?? 'Unknown').join(', ');
	const tone = { active: 'success', expired: 'warning', revoked: 'neutral' } as const;
</script>

<section class="card" aria-labelledby="keys-h">
	<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="keys-h" class="font-semibold">API keys</h2>
			<p class="text-muted text-xs">
				For scripts and other tools: <code class="text-fg">Authorization: Bearer rmm_k_…</code>. A key acts as {all ? 'its owner' : 'you'} and never with more.
				<a class="link" href="/developers">API reference</a>
			</p>
		</div>
		<Button variant="primary" icon={Plus} onclick={open}>Create key</Button>
	</header>
	<Async res={keys} compact>
		{#snippet children(list)}
			{#if list.length}
				<div class="overflow-x-auto">
					<table class="table">
						<thead>
							<tr>
								<th>Key</th>
								{#if all}<th>Owner</th>{/if}
								<th>Access</th>
								<th>Clients</th>
								<th>Last used</th>
								<th>Expires</th>
								<th><span class="sr-only">Actions</span></th>
							</tr>
						</thead>
						<tbody>
							{#each list as k (k.id)}
								<tr class={k.status === 'active' ? '' : 'text-muted'}>
									<td>
										<div class="font-medium">{k.name} {#if k.status !== 'active'}<Badge tone={tone[k.status]}>{k.status === 'revoked' ? 'Revoked' : 'Expired'}</Badge>{/if}</div>
										<div class="text-muted font-mono text-xs">{k.prefix}…</div>
										<div class="text-muted text-xs">{k.scopes.join(', ')}{k.permissions.length ? ` · ${k.permissions.join(', ')}` : ''}</div>
									</td>
									{#if all}<td>{k.owner_name} {#if k.service_account}<Badge>Service account</Badge>{/if}</td>{/if}
									<td><Badge tone={k.access === 'write' ? 'warning' : 'neutral'}>{k.access === 'write' ? 'Read and write' : 'Read-only'}</Badge><div class="text-muted text-xs">{k.rate_limit_per_min}/min</div></td>
									<td class="max-w-48 truncate text-sm" title={clientNames(k)}>{clientNames(k)}</td>
									<td class="whitespace-nowrap" title={k.last_used_at ? datetime(k.last_used_at) : undefined}>
										{k.last_used_at ? ago(k.last_used_at) : 'Never'}{#if k.last_used_ip}<div class="text-muted text-xs">{k.last_used_ip}</div>{/if}
									</td>
									<td class="whitespace-nowrap" title={k.expires_at ? datetime(k.expires_at) : undefined}>{k.expires_at ? datetime(k.expires_at) : 'Never'}</td>
									<td class="text-right">
										{#if k.status !== 'revoked'}<IconButton icon={Trash2} size="sm" label="Revoke {k.name}" onclick={() => revoke(k)} />{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<EmptyState compact icon={KeyRound} title="No API keys yet" description="Create one to let a script or another system read and change things here, within the limits you choose." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if creating}
	<Modal title="Create API key" description="Choose what the key may do. It can be narrower than its owner, never wider." onclose={() => (creating = false)} size="lg">
		<form id="key-form" class="space-y-4" onsubmit={create}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="k-name" hint="What it’s for, e.g. “Reporting script”." required><Input id="k-name" bind:value={form.name} required maxlength={100} /></Field>
				{#if all}
					<Field label="Acts as" id="k-owner" hint="Keys for people are made on their own account page.">
						<Select
							id="k-owner"
							bind:value={form.owner}
							onchange={loadOptions}
							options={[{ value: '', label: 'Me' }, ...accounts.filter((a) => !a.disabled).map((a) => ({ value: a.id, label: `${a.name} (service account)` }))]}
						/>
					</Field>
				{/if}
			</div>
			<div>
				<div class="label">Access</div>
				<Segmented
					label="Access"
					size="md"
					value={form.access}
					onchange={(v: 'read' | 'write') => (form.access = v)}
					options={[{ value: 'read', label: 'Read-only' }, ...(options?.can_write === false ? [] : [{ value: 'write' as const, label: 'Read and write' }])]}
				/>
				<p class="hint">{form.access === 'write' ? 'Can create tickets, run saved scripts and acknowledge alerts, within the scopes below.' : 'Can only read.'}</p>
			</div>
			<fieldset>
				<legend class="label">Scopes</legend>
				<div class="grid gap-2 sm:grid-cols-2">
					{#each options?.groups ?? [] as g (g.id)}
						<Checkbox checked={form.scopes.includes(g.id)} onchange={(on) => (form.scopes = toggle(form.scopes, g.id, on))}>{g.label}</Checkbox>
					{/each}
				</div>
			</fieldset>
			{#if options?.permissions.length}
				<fieldset>
					<legend class="label">Permissions</legend>
					<p class="hint mb-2">Only for what needs one (endpoint protection data needs “See protection”). Without them the key has none, whatever its owner holds.</p>
					<div class="grid gap-2 sm:grid-cols-2">
						{#each options.permissions as p (p)}
							<Checkbox checked={form.permissions.includes(p)} onchange={(on) => (form.permissions = toggle(form.permissions, p, on))}>{permLabels[p] ?? p}</Checkbox>
						{/each}
					</div>
				</fieldset>
			{/if}
			<div class="space-y-2">
				<Switch bind:checked={form.limited}>Limit to some clients</Switch>
				{#if form.limited}
					<div class="border-border max-h-44 space-y-2 overflow-y-auto rounded-md border p-3">
						{#each clients.list as c (c.id)}
							<div><Checkbox checked={form.client_ids.includes(c.id)} onchange={(on) => (form.client_ids = toggle(form.client_ids, c.id, on))}>{c.name}</Checkbox></div>
						{/each}
					</div>
				{:else}
					<p class="hint">Otherwise every client the owner can see, now and later.</p>
				{/if}
			</div>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Expires" id="k-exp">
					<Select
						id="k-exp"
						bind:value={form.expires}
						options={[{ value: '30', label: 'In 30 days' }, { value: '90', label: 'In 90 days' }, { value: '365', label: 'In a year' }, { value: 'never', label: 'Never' }]}
					/>
				</Field>
				<Field label="Rate limit" id="k-rate" hint="Requests per minute."><Input id="k-rate" type="number" min="1" max="100000" bind:value={form.rate} /></Field>
			</div>
		</form>
		{#snippet footer()}
			<Button onclick={() => (creating = false)}>Cancel</Button>
			<Button variant="primary" type="submit" form="key-form" loading={busy} disabled={!form.scopes.length || (form.limited && !form.client_ids.length)}>Create key</Button>
		{/snippet}
	</Modal>
{/if}

{#if created}
	<Modal title="Copy your key now" description="It is shown once. Only a hash is kept, so it can’t be shown again." onclose={() => (created = null)}>
		<CodeBlock code={created.token} label="API key for {created.name}" />
		<p class="text-muted mt-3 text-sm">Send it as <code class="text-fg">Authorization: Bearer {created.token.slice(0, 12)}…</code> to <code class="text-fg">/api/v1</code>. Treat it like a password.</p>
		{#snippet footer()}<Button variant="primary" onclick={() => (created = null)}>I’ve copied it</Button>{/snippet}
	</Modal>
{/if}
