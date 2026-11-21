<script lang="ts">
	import { Popover } from 'bits-ui';
	import { cx } from '#lib/format.js';
	import { BLOCKS, type DocContext } from '#lib/docs/blocks.js';
	import { segments } from '#lib/docs/markdown.js';
	import CredentialCard from '#lib/components/vault/CredentialCard.svelte';
	import CredentialNotice from '#lib/components/vault/CredentialNotice.svelte';
	import '#lib/docs/doc.css';

	/**
	 * A rendered document: Markdown (raw HTML never rendered; see docs/markdown.ts) with the
	 * registered blocks as components. `[name](vault:<id>)` links are chips that open the
	 * credential in a popover.
	 */
	let { source, ctx, class: klass = '', empty = 'This page is empty.' }: { source: string; ctx: DocContext; class?: string; empty?: string } = $props();

	const segs = $derived(segments(source));

	// --- credential chips -----------------------------------------------------------------------
	let chip = $state<{ el: HTMLElement; id: string; label: string } | null>(null);
	let open = $state(false);
	function onclick(e: MouseEvent) {
		const link = ctx.openDoc && !(e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button) ? (e.target as HTMLElement).closest<HTMLAnchorElement>('a[data-doc]') : null;
		if (link) {
			e.preventDefault();
			ctx.openDoc!(link.dataset.doc ?? '');
			return;
		}
		const el = (e.target as HTMLElement).closest<HTMLElement>('button.doc-chip[data-vault]');
		if (!el) return;
		e.preventDefault();
		chip = { el, id: (el.dataset.vault ?? '').toLowerCase(), label: el.textContent?.trim() ?? '' };
		open = true;
	}
	const chipItem = $derived(chip ? ctx.credentials.get(chip.id) : undefined);

	// `doc:` links are relative to the Docs tab; elsewhere they point at the client's page.
	let root = $state<HTMLElement | null>(null);
	$effect(() => {
		void segs;
		const href = ctx.docHref;
		if (!root || !href) return;
		for (const a of root.querySelectorAll<HTMLAnchorElement>('a[data-doc]')) a.href = href(a.dataset.doc ?? '');
	});
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions (the chips are buttons; this only delegates their clicks) -->
<div bind:this={root} class={cx('doc-view doc-prose', klass)} {onclick}>
	{#each segs as s, i (i)}
		{#if s.kind === 'md'}
			{@html s.html}
		{:else}
			{@const B = BLOCKS[s.name].component}
			<B seg={s} {ctx} />
		{/if}
	{:else}
		<p class="text-muted text-sm">{empty}</p>
	{/each}
</div>

{#if chip}
	<Popover.Root bind:open onOpenChange={(o) => !o && setTimeout(() => (chip = open ? chip : null), 200)}>
		<Popover.Portal>
			<Popover.Content
				customAnchor={chip.el}
				side="bottom"
				align="start"
				sideOffset={6}
				collisionPadding={12}
				onCloseAutoFocus={(e) => {
					e.preventDefault();
					chip?.el.focus();
				}}
				role="dialog"
				aria-label={chipItem?.name ?? chip.label}
				class="border-border bg-raised shadow-pop z-50 w-[min(24rem,calc(100vw-1.5rem))] rounded-lg border p-4 outline-none"
			>
				{#if chipItem}
					<CredentialCard item={chipItem} label={chip.label} flat />
				{:else}
					<CredentialNotice label={chip.label} hidden={ctx.credentialsHidden} problem={ctx.vaultProblem} />
				{/if}
			</Popover.Content>
		</Popover.Portal>
	</Popover.Root>
{/if}
