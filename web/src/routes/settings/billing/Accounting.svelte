<script lang="ts">
	import { Link2, PlugZap, RefreshCw, Unplug } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import type { AccountingConnection, AccountingProvider, SyncResult } from '#lib/billing/types.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';

	const manage = $derived(allowed('billing.manage'));
	const conns = resource(() => api.get<AccountingConnection[]>('/billing/accounting'));

	type Draft = { client_id: string; client_secret: string; item_id: string; account_code: string; tax_type: string };
	let drafts = $state<Partial<Record<AccountingProvider, Draft>>>({});
	$effect(() => {
		for (const c of conns.data ?? []) {
			if (drafts[c.provider]) continue;
			drafts[c.provider] = {
				client_id: c.client_id, client_secret: '', item_id: c.settings.item_id ?? '', account_code: c.settings.account_code ?? '', tax_type: c.settings.tax_type ?? ''
			};
		}
	});
	const anyConnected = $derived((conns.data ?? []).find((c) => c.connected));
	let busy = $state<string | null>(null);

	async function saveApp(c: AccountingConnection): Promise<boolean> {
		const d = drafts[c.provider]!;
		if (!d.client_id.trim()) {
			toast.error('Enter the app’s client id.');
			return false;
		}
		if (!c.has_secret && !d.client_secret.trim()) {
			toast.error('Enter the app’s client secret.');
			return false;
		}
		const settings = c.provider === 'qbo' ? { item_id: d.item_id.trim() } : { account_code: d.account_code.trim(), tax_type: d.tax_type.trim() };
		busy = `save-${c.provider}`;
		const ok = await attempt(() => api.put(`/billing/accounting/${c.provider}`, { client_id: d.client_id.trim(), client_secret: d.client_secret.trim() || null, settings }), `${c.label} settings saved.`);
		busy = null;
		if (ok) {
			d.client_secret = '';
			conns.reload();
		}
		return ok;
	}
	async function connect(c: AccountingConnection) {
		const d = drafts[c.provider]!;
		if ((d.client_id.trim() !== c.client_id || d.client_secret.trim()) && !(await saveApp(c))) return;
		busy = `connect-${c.provider}`;
		try {
			const { url } = await api.post<{ url: string }>(`/billing/accounting/${c.provider}/connect`);
			window.location.href = url;
		} catch (e) {
			toast.error(e);
			busy = null;
		}
	}
	async function disconnect() {
		const c = anyConnected;
		const ok = await confirmAction({ title: `Disconnect ${c?.label ?? 'the accounting system'}?`, message: 'Invoices stop syncing. Ones already pushed stay there.', confirmLabel: 'Disconnect', danger: true });
		if (ok && (await attempt(() => api.del('/billing/accounting'), 'Disconnected.'))) conns.reload();
	}
	async function sync() {
		busy = 'sync';
		try {
			const r = await api.post<SyncResult>('/billing/accounting/sync');
			const msg = `Pushed ${plural(r.pushed, 'invoice')}, ${plural(r.paid, 'payment')} picked up.`;
			if (r.errors.length) toast.error(`${msg} ${plural(r.errors.length, 'error')}: ${r.errors.slice(0, 3).join('; ')}${r.errors.length > 3 ? '…' : ''}`);
			else toast.success(msg);
		} catch (e) {
			toast.error(e);
		}
		busy = null;
		conns.reload();
	}
</script>

<section class="card" aria-labelledby="bs-acct-h">
	<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="bs-acct-h" class="font-semibold">Accounting</h2>
			<p class="text-muted text-xs">Finalised invoices and credit notes are pushed to QuickBooks Online or Xero, and payments recorded there mark them paid here. Connect one at a time.</p>
		</div>
		{#if manage && anyConnected}
			<div class="flex gap-2">
				<Button icon={RefreshCw} loading={busy === 'sync'} onclick={sync}>Sync now</Button>
				<Button icon={Unplug} variant="danger-ghost" onclick={disconnect}>Disconnect</Button>
			</div>
		{/if}
	</header>
	<Async res={conns} compact>
		{#snippet children(list)}
			<div class="divide-border grid divide-y md:grid-cols-2 md:divide-x md:divide-y-0">
				{#each list as c (c.provider)}
					{@const d = drafts[c.provider]}
					<div class="space-y-3 p-5">
						<div class="flex flex-wrap items-center gap-2">
							<h3 class="font-semibold">{c.label}</h3>
							{#if c.connected}<Badge tone="success" dot>Connected{c.tenant_name ? ` to ${c.tenant_name}` : ''}</Badge>{:else}<Badge>Not connected</Badge>{/if}
						</div>
						{#if c.connected}
							<p class="text-muted text-xs">
								Connected {datetime(c.connected_at)} · last sync {c.last_sync_at ? ago(c.last_sync_at) : 'never'}
							</p>
						{/if}
						{#if c.last_error}<p class="text-danger text-xs break-words" role="status">Last error: {c.last_error}</p>{/if}
						{#if d}
							<form
								class="space-y-3"
								onsubmit={(e) => {
									e.preventDefault();
									saveApp(c);
								}}
							>
								<fieldset class="space-y-3" disabled={!manage}>
									<div>
										<span class="label">Redirect URI</span>
										<div class="flex items-center gap-2">
											<code class="bg-sunken border-border min-w-0 flex-1 truncate rounded-md border px-2 py-1 text-xs" title={c.redirect_uri}>{c.redirect_uri}</code>
											<CopyButton text={c.redirect_uri} label="Copy redirect URI" />
										</div>
										<p class="hint">Add this to the app you create in the {c.provider === 'qbo' ? 'Intuit developer portal' : 'Xero developer portal'}.</p>
									</div>
									<Field label="Client id" id="ac-{c.provider}-id"><Input id="ac-{c.provider}-id" bind:value={d.client_id} autocomplete="off" maxlength={200} /></Field>
									<Field label="Client secret" id="ac-{c.provider}-secret" hint={c.has_secret ? 'Saved. Enter a new one to replace it.' : undefined}>
										<Input id="ac-{c.provider}-secret" type="password" bind:value={d.client_secret} autocomplete="new-password" placeholder={c.has_secret ? '••••••••' : ''} />
									</Field>
									{#if c.provider === 'qbo'}
										<Field label="Item id" id="ac-qbo-item" hint="The QuickBooks product/service every line is booked to."><Input id="ac-qbo-item" bind:value={d.item_id} placeholder="1" /></Field>
									{:else}
										<div class="grid grid-cols-2 gap-3">
											<Field label="Account code" id="ac-xero-acct" hint="Revenue account."><Input id="ac-xero-acct" bind:value={d.account_code} placeholder="200" /></Field>
											<Field label="Tax type" id="ac-xero-tax"><Input id="ac-xero-tax" bind:value={d.tax_type} placeholder="OUTPUT" /></Field>
										</div>
									{/if}
								</fieldset>
								{#if manage}
									<div class="flex flex-wrap justify-end gap-2">
										<Button type="submit" loading={busy === `save-${c.provider}`}>Save</Button>
										<Button
											variant={c.connected ? 'secondary' : 'primary'}
											icon={c.connected ? Link2 : PlugZap}
											loading={busy === `connect-${c.provider}`}
											disabled={!!anyConnected && anyConnected.provider !== c.provider}
											title={anyConnected && anyConnected.provider !== c.provider ? `Disconnect ${anyConnected.label} first` : undefined}
											onclick={() => connect(c)}
										>
											{c.connected ? 'Reconnect' : `Connect ${c.label}`}
										</Button>
									</div>
								{/if}
							</form>
						{/if}
					</div>
				{/each}
			</div>
		{/snippet}
	</Async>
</section>
