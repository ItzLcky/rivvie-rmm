<script lang="ts">
	import { onDestroy } from 'svelte';
	import { Eye, EyeOff, FileText, History, KeyRound, Pencil, Plus, Search, Timer, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { webUrl } from '#lib/docs/markdown.js';
	import type { VaultDetail, VaultItem } from '#lib/docs/types.js';
	import { REVEAL_MS, canManageVault, revealHistory, secretError, vaultAccess, vaultProblem } from '#lib/docs/vault.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import Drawer from '#lib/ui/Drawer.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import CredentialCard from './CredentialCard.svelte';
	import VaultForm from './VaultForm.svelte';
	import VaultState from './VaultState.svelte';

	/** A client's password vault: the Passwords tab of the client page. */
	let { clientId, clientName }: { clientId: string; clientName: string } = $props();

	const access = vaultAccess();
	const list = resource(() => (access === 'ok' ? api.get<VaultItem[]>(`/clients/${clientId}/vault`) : Promise.resolve([] as VaultItem[])));
	const problem = $derived(access === 'mfa' ? 'mfa' : access === 'none' ? 'perm' : list.error ? vaultProblem(list.error) : null);
	const manage = canManageVault();

	let q = $state('');
	const rows = $derived.by(() => {
		const s = q.trim().toLowerCase();
		const all = list.data ?? [];
		return s ? all.filter((r) => `${r.name} ${r.username} ${r.url}`.toLowerCase().includes(s)) : all;
	});

	// --- the drawer (?item=) --------------------------------------------------------------------
	const itemId = $derived(param('item') || null);
	const detail = resource(() => (itemId && access === 'ok' ? api.get<VaultDetail>(`/vault/${itemId}`) : Promise.resolve(null)), { keep: false });
	const open = (id: string | null) => setParams({ item: id }, { push: !!id });

	// Earlier passwords, revealed one at a time for 30 seconds.
	let old = $state<{ id: number; value: string; until: number } | null>(null);
	let oldError = $state<{ id: number; message: string } | null>(null);
	let now = $state(Date.now());
	const timer = setInterval(() => {
		if (!old) return;
		now = Date.now();
		if (old.until <= now) old = null;
	}, 1000);
	onDestroy(() => clearInterval(timer));
	$effect(() => {
		void itemId;
		old = null;
		oldError = null;
	});
	async function showOld(d: VaultDetail, h: number) {
		oldError = null;
		try {
			old = { id: h, value: await revealHistory(d.id, h), until: Date.now() + REVEAL_MS };
			now = Date.now();
		} catch (e) {
			oldError = { id: h, message: secretError(e) };
		}
	}

	// --- create, edit, delete -------------------------------------------------------------------
	let form = $state<{ item: VaultItem | null } | null>(null);
	let busy = $state(false);
	function saved(d: VaultDetail) {
		const isNew = !form?.item;
		form = null;
		list.reload();
		if (isNew) open(d.id);
		else if (detail.data?.id === d.id) detail.set(d);
	}
	async function remove(d: VaultDetail) {
		const ok = await confirmAction({
			title: `Delete ${d.name}?`,
			message: `The password, notes, TOTP secret and password history are deleted for good.${d.linked_docs.length ? ` ${plural(d.linked_docs.length, 'page links', 'pages link')} to it and will show “Credential not found”.` : ''}`,
			confirmLabel: 'Delete credential',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/vault/${d.id}`), `${d.name} deleted.`))) {
			open(null);
			list.reload();
		}
	}
</script>

{#snippet nameCell(r: VaultItem)}
	<a class="hover:text-accent flex items-center gap-2 font-medium" href="?tab=passwords&item={r.id}">
		<KeyRound class="text-subtle size-3.5 shrink-0" aria-hidden="true" />{r.name}
	</a>
{/snippet}
{#snippet userCell(r: VaultItem)}<span class="font-mono text-xs">{r.username}</span>{/snippet}
{#snippet urlCell(r: VaultItem)}
	{@const w = webUrl(r.url)}
	{#if w}<a class="link block max-w-[18rem] truncate text-xs" href={w} target="_blank" rel="noopener noreferrer">{r.url}</a>{:else}<span class="text-muted block max-w-[18rem] truncate font-mono text-xs">{r.url}</span>{/if}
{/snippet}
{#snippet totpCell(r: VaultItem)}
	{#if r.has_totp}<span class="text-muted inline-flex items-center gap-1 text-xs"><Timer class="size-3.5" aria-hidden="true" />TOTP</span>{/if}
{/snippet}
{#snippet docsCell(r: VaultItem)}<span class="tabular text-muted">{r.docs || ''}</span>{/snippet}
{#snippet changedCell(r: VaultItem)}<span class="text-muted text-xs" title={r.password_changed_at ? datetime(r.password_changed_at) : undefined}>{r.has_password ? (r.password_changed_at ? ago(r.password_changed_at) : '—') : 'No password'}</span>{/snippet}

{#if problem}
	<div class="card"><VaultState {problem} /></div>
{:else}
	<DataTable
		id="client-vault"
		caption="Passwords of {clientName}"
		{rows}
		columns={[
			{ id: 'name', label: 'Name', cell: nameCell, hideable: false },
			{ id: 'username', label: 'Username', cell: userCell },
			{ id: 'url', label: 'URL', cell: urlCell, from: 'md' },
			{ id: 'totp', label: 'TOTP', cell: totpCell, from: 'sm' },
			{ id: 'docs', label: 'Pages', cell: docsCell, align: 'right', from: 'lg' },
			{ id: 'changed', label: 'Password changed', cell: changedCell, from: 'sm' }
		] satisfies Column<VaultItem>[]}
		key={(r) => r.id} loading={list.loading} busy={list.busy} rowHref={(r) => `?tab=passwords&item=${r.id}`} scroll={false}>
		{#snippet toolbar()}
			<Input icon={Search} class="w-full max-w-xs" bind:value={q} placeholder="Filter by name, username or URL" aria-label="Filter passwords" />
			{#if manage}<Button variant="primary" icon={Plus} class="ml-auto sm:ml-0" onclick={() => (form = { item: null })}>New password</Button>{/if}
		{/snippet}
		{#snippet empty()}
			{#if q}
				<p class="text-muted py-10 text-center text-sm">No credential matches “{q}”.</p>
			{:else}
				<EmptyState icon={KeyRound} title="No passwords yet" description="Admin logins, Wi-Fi keys, vendor portals: each is encrypted, and every reveal is written to the audit log." />
			{/if}
		{/snippet}
		{#snippet footer()}
			<p class="text-muted px-4 py-2.5 text-xs">Secrets are encrypted per client and never sent in lists. Revealing a password, notes or a TOTP code is logged and limited to 60 in 5 minutes.</p>
		{/snippet}
	</DataTable>
{/if}

<Drawer open={!!itemId} title="Credential" side="right" width="w-[30rem]" onclose={() => open(null)}>
	<div class="px-5 pb-6">
		{#if detail.error && vaultProblem(detail.error)}
			<VaultState problem={vaultProblem(detail.error)!} compact />
		{:else}
		<Async res={detail}>
			{#snippet children(d)}
				{#if d}
					<div class="space-y-6">
						<CredentialCard item={d} flat />
						<p class="text-muted -mt-3 text-xs">Updated {ago(d.updated_at)}{d.updated_by_name ? ` by ${d.updated_by_name}` : ''}</p>
						{#if manage}
							<div class="flex flex-wrap gap-2">
								<Button size="sm" icon={Pencil} onclick={() => (form = { item: d })}>Edit</Button>
								<Button size="sm" variant="danger-ghost" icon={Trash2} onclick={() => remove(d)}>Delete</Button>
							</div>
						{/if}
						<section aria-labelledby="cred-pages-h">
							<h3 id="cred-pages-h" class="mb-2 flex items-center gap-1.5 text-sm font-semibold"><FileText class="text-muted size-4" aria-hidden="true" />Linked pages</h3>
							{#if d.linked_docs.length}
								<ul class="space-y-1 text-sm">
									{#each d.linked_docs as p (p.id)}<li><a class="link" href="?tab=docs&doc={p.id}">{p.title}</a></li>{/each}
								</ul>
							{:else}
								<p class="text-muted text-sm">No page links to it. Add it to a page with Insert block → Credential.</p>
							{/if}
						</section>
						<section aria-labelledby="cred-hist-h">
							<h3 id="cred-hist-h" class="mb-2 flex items-center gap-1.5 text-sm font-semibold"><History class="text-muted size-4" aria-hidden="true" />Password history</h3>
							{#if d.history.length}
								<ul class="divide-border border-border divide-y rounded-md border text-sm">
									{#each d.history as h (h.id)}
										<li class="px-3 py-2">
											<div class="flex items-center gap-2">
												<span class="min-w-0 flex-1">
													Replaced {ago(h.replaced_at)}<span class="text-muted text-xs">{h.replaced_by_name ? ` by ${h.replaced_by_name}` : ''}</span>
												</span>
												{#if old?.id === h.id}
													<span class="text-muted tabular text-xs">{Math.max(0, Math.ceil((old.until - now) / 1000))} s</span>
													<IconButton icon={EyeOff} size="sm" label="Hide this password" onclick={() => (old = null)} />
												{:else}
													<IconButton icon={Eye} size="sm" label="Reveal the password replaced {ago(h.replaced_at)}" onclick={() => showOld(d, h.id)} />
												{/if}
											</div>
											{#if old?.id === h.id}<p class="bg-sunken mt-1.5 rounded px-2 py-1 font-mono text-xs break-all" aria-live="polite">{old.value}</p>{/if}
											{#if oldError?.id === h.id}<p class="text-danger mt-1 text-xs" role="alert">{oldError.message}</p>{/if}
										</li>
									{/each}
								</ul>
							{:else}
								<p class="text-muted text-sm">The last 10 passwords are kept here when it changes.</p>
							{/if}
						</section>
					</div>
				{/if}
			{/snippet}
		</Async>
		{/if}
	</div>
</Drawer>

{#if form}
	<Modal title={form.item ? `Edit ${form.item.name}` : 'New password'} description={clientName} onclose={() => (form = null)} size="md">
		<VaultForm {clientId} item={form.item} formId="vault-form" bind:busy onsaved={saved} />
		{#snippet footer()}
			<Button onclick={() => (form = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="vault-form" loading={busy}>Save</Button>
		{/snippet}
	</Modal>
{/if}
