<script lang="ts">
	import { LockKeyhole } from '@lucide/svelte';
	import { cx } from '#lib/format.js';
	import type { DocContext } from '#lib/docs/blocks.js';
	import { chipSource } from '#lib/docs/context.js';
	import type { DocDetail } from '#lib/docs/types.js';
	import { vaultAccess } from '#lib/docs/vault.js';
	import DocView from './DocView.svelte';

	/** The strip under a page's header: its linked credentials as chips, or why they're hidden. */
	let { doc: d, ctx, class: klass = '' }: { doc: DocDetail; ctx: DocContext; class?: string } = $props();
</script>

{#if d.credentials.length || d.credentials_hidden}
	<div class={cx('border-border bg-sunken/40 flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b py-2.5', klass)}>
		{#if d.credentials.length}
			<span class="text-muted text-xs font-medium">Linked credentials</span>
			<DocView source={chipSource(d)} {ctx} class="!text-sm !leading-7" />
		{/if}
		{#if d.credentials_hidden}
			<p class="text-muted flex items-center gap-1.5 text-xs">
				<LockKeyhole class="size-3.5 shrink-0" aria-hidden="true" />
				{#if vaultAccess() === 'mfa'}
					This page links to credentials. Turn on <a class="link" href="/account#two-factor">two-factor authentication</a> to see them.
				{:else}
					This page links to credentials you don’t have access to.
				{/if}
			</p>
		{/if}
	</div>
{/if}
