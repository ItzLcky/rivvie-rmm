<script lang="ts">
	import { KeyRound, LockKeyhole, ShieldAlert } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { vaultAccess, type VaultProblem } from '#lib/docs/vault.js';

	/**
	 * In place of a credential that can't be shown: no vault access, no two-factor
	 * authentication, the vault unavailable, or the item gone.
	 */
	let { label = '', hidden = false, problem = null, children }: { label?: string; hidden?: boolean; problem?: VaultProblem | null; children?: Snippet } = $props();
	const access = $derived(vaultAccess());
	const reason = $derived(
		access === 'none' || problem === 'perm' ? 'none' : access === 'mfa' || problem === 'mfa' ? 'mfa' : problem === 'key' ? 'key' : hidden ? 'none' : 'missing'
	);
</script>

<div class="doc-slot">
	{#if reason === 'missing'}<KeyRound class="text-subtle size-4 shrink-0" aria-hidden="true" />{:else if reason === 'mfa'}<ShieldAlert class="text-warning size-4 shrink-0" aria-hidden="true" />{:else}<LockKeyhole class="text-subtle size-4 shrink-0" aria-hidden="true" />{/if}
	<div class="min-w-0 flex-1">
		{#if label}<p class="text-sm font-medium">{label}</p>{/if}
		<p class="text-muted text-xs">
			{#if reason === 'none'}
				You don’t have access to credentials.
			{:else if reason === 'mfa'}
				Turn on <a class="link" href="/account#two-factor">two-factor authentication</a> to see credentials.
			{:else if reason === 'key'}
				The vault is unavailable: the server needs RMM_DATA_KEY.
			{:else}
				Credential not found. It was deleted, or it belongs to another client.
			{/if}
		</p>
	</div>
	{@render children?.()}
</div>
