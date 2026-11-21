<script lang="ts">
	import { KeyRound, Link2 } from '@lucide/svelte';
	import { parseCredential } from '#lib/docs/markdown.js';
	import type { BlockProps } from '#lib/docs/blocks.js';
	import Button from '#lib/ui/Button.svelte';
	import CredentialCard from '#lib/components/vault/CredentialCard.svelte';
	import CredentialNotice from '#lib/components/vault/CredentialNotice.svelte';
	import BlockError from './BlockError.svelte';

	/**
	 * A vault item (`item: vault:<id>`) as a card, or an empty slot (`label:` only) a template
	 * leaves for one. In the editor's preview a slot (or a missing item) can be filled from the
	 * vault, which rewrites the block.
	 */
	let { seg, ctx }: BlockProps = $props();
	const parsed = $derived(parseCredential(seg.body));
	const item = $derived(parsed.item ? ctx.credentials.get(parsed.item) : undefined);
</script>

{#if parsed.error}
	<BlockError {seg} message={parsed.error} />
{:else if !parsed.item}
	<div class="doc-block doc-slot">
		<KeyRound class="text-subtle size-4 shrink-0" aria-hidden="true" />
		<div class="min-w-0 flex-1">
			<p class="text-sm font-medium">{parsed.label || 'Credential'}</p>
			<p class="text-muted text-xs">No credential linked</p>
		</div>
		{#if ctx.chooseCredential}
			<Button size="sm" icon={Link2} onclick={() => ctx.chooseCredential!(seg, parsed.label)}>Choose credential</Button>
		{/if}
	</div>
{:else if item}
	<div class="doc-block"><CredentialCard {item} label={parsed.label} /></div>
{:else}
	<div class="doc-block">
		<CredentialNotice label={parsed.label} hidden={ctx.credentialsHidden} problem={ctx.vaultProblem}>
			{#if ctx.chooseCredential}
				<Button size="sm" icon={Link2} onclick={() => ctx.chooseCredential!(seg, parsed.label)}>Choose another</Button>
			{/if}
		</CredentialNotice>
	</div>
{/if}
