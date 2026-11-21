<script lang="ts">
	import { Check, KeyRound, Plus, Search, Timer } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { cx } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import type { VaultDetail, VaultItem } from '#lib/docs/types.js';
	import { canManageVault, vaultAccess, vaultProblem } from '#lib/docs/vault.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import VaultForm from './VaultForm.svelte';
	import VaultState from './VaultState.svelte';

	/**
	 * Choose one of the client's credentials, or create one (named after the slot's label), for a
	 * credential block. Returns its metadata; the caller writes `item: vault:<id>`.
	 */
	let {
		clientId,
		label = '',
		current = null,
		onpick,
		onclose
	}: { clientId: string; label?: string; current?: string | null; onpick: (item: VaultItem) => void; onclose: () => void } = $props();

	const access = vaultAccess();
	const list = resource(() => (access === 'ok' ? api.get<VaultItem[]>(`/clients/${clientId}/vault`) : Promise.resolve([] as VaultItem[])));
	const problem = $derived(access === 'mfa' ? 'mfa' : access === 'none' ? 'perm' : vaultProblem(list.error));
	let q = $state('');
	let creating = $state(false);
	let busy = $state(false);
	let chosen = $state<string | null>(null);
	const shown = $derived.by(() => {
		const rows = list.data ?? [];
		const s = q.trim().toLowerCase();
		if (!s) return rows;
		return rows.filter((r) => `${r.name} ${r.username} ${r.url}`.toLowerCase().includes(s));
	});
	function confirm() {
		const it = list.data?.find((r) => r.id === chosen);
		if (it) onpick(it);
	}
</script>

<Modal title={creating ? 'New credential' : 'Choose a credential'} description={label ? `For “${label}”` : undefined} {onclose} size="md">
	{#if problem}
		<VaultState {problem} compact />
	{:else if creating}
		<VaultForm {clientId} initialName={label} formId="picker-new" bind:busy onsaved={(d: VaultDetail) => onpick(d)} />
	{:else}
		<div class="space-y-3">
			<Input icon={Search} bind:value={q} placeholder="Filter by name, username or URL" aria-label="Filter credentials" />
			<Async res={list} compact>
				{#snippet children(rows)}
					{#if !rows.length}
						<EmptyState compact icon={KeyRound} title="No credentials yet" description="Create the first one for this client: it’s stored encrypted in the vault." />
					{:else if !shown.length}
						<p class="text-muted py-6 text-center text-sm">Nothing matches “{q}”.</p>
					{:else}
						<div role="radiogroup" aria-label="Credentials" class="border-border relative max-h-[22rem] overflow-x-hidden divide-y divide-[var(--border)] overflow-y-auto rounded-md border">
							{#each shown as r (r.id)}
								{@const on = chosen === r.id}
								<label
									class={cx('hover:bg-hover/60 grid w-full cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-3 px-3 py-2 text-left has-[:focus-visible]:outline-2 has-[:focus-visible]:-outline-offset-2 has-[:focus-visible]:outline-[var(--focus)]', on && 'bg-accent-soft')}
									ondblclick={() => onpick(r)}
								>
									<input type="radio" name="vault-pick" class="sr-only" value={r.id} bind:group={chosen} />
									<KeyRound class={cx('size-4 shrink-0', on ? 'text-accent' : 'text-subtle')} aria-hidden="true" />
									<span class="min-w-0 flex-1">
										<span class="block truncate text-sm font-medium">{r.name}{#if r.id === current}<span class="text-muted font-normal"> (linked now)</span>{/if}</span>
										<span class="text-muted block truncate text-xs">{[r.username, r.url].filter(Boolean).join(' · ') || 'No username'}</span>
									</span>
									<span class="text-muted inline-flex shrink-0 items-center gap-1 text-xs">{#if r.has_totp}<Timer class="size-3.5" aria-hidden="true" />TOTP{/if}</span>
									<Check class={cx('text-accent size-4 shrink-0', !on && 'invisible')} aria-hidden="true" />
								</label>
							{/each}
						</div>
					{/if}
				{/snippet}
			</Async>
		</div>
	{/if}
	{#snippet footer()}
		{#if creating}
			<Button onclick={() => (creating = false)}>Back</Button>
			<Button variant="primary" type="submit" form="picker-new" loading={busy}>Create and link</Button>
		{:else}
			{#if !problem && canManageVault()}<Button class="mr-auto" icon={Plus} onclick={() => (creating = true)}>New credential</Button>{/if}
			<Button onclick={onclose}>Cancel</Button>
			{#if !problem}<Button variant="primary" disabled={!chosen} onclick={confirm}>Link credential</Button>{/if}
		{/if}
	{/snippet}
</Modal>
