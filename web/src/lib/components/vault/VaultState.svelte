<script lang="ts">
	import { KeyRound, LockKeyhole, ServerCog, ShieldAlert } from '@lucide/svelte';
	import type { VaultProblem } from '#lib/docs/vault.js';
	import Button from '#lib/ui/Button.svelte';

	/** Why the vault can't be used here, and what to do about it: designed states, not errors. */
	let { problem, compact = false }: { problem: VaultProblem; compact?: boolean } = $props();
</script>

<div class="flex flex-col items-center justify-center gap-2 px-6 text-center {compact ? 'py-6' : 'py-12'}">
	{#if problem === 'mfa'}
		<div class="bg-warning-soft text-warning mb-1 flex size-11 items-center justify-center rounded-lg"><ShieldAlert class="size-5" aria-hidden="true" /></div>
		<p class="text-[0.9375rem] font-semibold">Turn on two-factor authentication</p>
		<p class="text-muted max-w-md text-sm">The vault holds every client’s passwords, so using it needs two-factor authentication on your account, as well as permission.</p>
		<Button class="mt-2" variant="primary" icon={ShieldAlert} href="/account#two-factor">Set up two-factor authentication</Button>
	{:else if problem === 'key'}
		<div class="bg-sunken text-muted mb-1 flex size-11 items-center justify-center rounded-lg"><ServerCog class="size-5" aria-hidden="true" /></div>
		<p class="text-[0.9375rem] font-semibold">The vault isn’t set up on this server</p>
		<p class="text-muted max-w-md text-sm">
			Passwords are encrypted with a key that only the server holds. Set <code class="bg-sunken border-border rounded border px-1 font-mono text-xs">RMM_DATA_KEY</code>
			(32 random bytes, e.g. <code class="bg-sunken border-border rounded border px-1 font-mono text-xs">openssl rand -hex 32</code>) in the server’s environment and restart it. Keep a copy somewhere safe: without it the vault can’t be opened.
		</p>
	{:else if problem === 'perm'}
		<div class="bg-sunken text-muted mb-1 flex size-11 items-center justify-center rounded-lg"><LockKeyhole class="size-5" aria-hidden="true" /></div>
		<p class="text-[0.9375rem] font-semibold">You don’t have access to credentials</p>
		<p class="text-muted max-w-md text-sm">An admin can give you the “See passwords” permission under Company settings → Users.</p>
	{:else}
		<div class="bg-sunken text-muted mb-1 flex size-11 items-center justify-center rounded-lg"><KeyRound class="size-5" aria-hidden="true" /></div>
		<p class="text-[0.9375rem] font-semibold">This credential no longer exists</p>
		<p class="text-muted max-w-md text-sm">It was deleted, or it belongs to a client you can’t see.</p>
	{/if}
</div>
