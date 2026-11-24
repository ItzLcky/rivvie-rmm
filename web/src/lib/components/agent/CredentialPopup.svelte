<script lang="ts">
	import { api } from '#lib/api.js';
	import CredentialCard from '#lib/components/vault/CredentialCard.svelte';
	import VaultState from '#lib/components/vault/VaultState.svelte';
	import type { VaultDetail } from '#lib/docs/types.js';
	import { vaultProblem } from '#lib/docs/vault.js';
	import { resource } from '#lib/resource.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Modal from '#lib/ui/Modal.svelte';

	/** A managed credential (recovery key, local admin password) in a dialog, read-only. */
	let { itemId, title, onclose }: { itemId: string; title: string; onclose: () => void } = $props();
	const detail = resource(() => api.get<VaultDetail>(`/vault/${itemId}`));
</script>

<Modal {title} {onclose}>
	{#if detail.error && vaultProblem(detail.error)}
		<VaultState problem={vaultProblem(detail.error)!} compact />
	{:else}
		<Async res={detail}>
			{#snippet children(d)}
				<CredentialCard item={d} flat />
				<p class="text-muted mt-3 text-xs">Kept by the server: its password changes only when the device's key or password does. Revealing it is logged.</p>
			{/snippet}
		</Async>
	{/if}
</Modal>
