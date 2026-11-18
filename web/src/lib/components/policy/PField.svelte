<script lang="ts">
	import { CornerLeftUp, PencilLine, RotateCcw } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { cx } from '#lib/format.js';
	import { fieldCtx } from '#lib/policy/fields.svelte.js';
	import { fieldLabel } from '#lib/policy/policy.js';

	/**
	 * One field of a policy form, with where its value comes from in the set being edited:
	 * inherited from a set above (and which), or overridden here (tinted, with Reset). With a
	 * `label` it lays out like `Field`; without one (switches, checkbox groups) the control
	 * carries its own label and the source sits beside it.
	 */
	let {
		path,
		name,
		label,
		id,
		hint,
		error,
		class: klass = '',
		children
	}: {
		/** The config field (dotted: `params.threshold`). */
		path: string;
		/** For the Reset button's name; defaults to the label. */
		name?: string;
		label?: string;
		id?: string;
		hint?: string | Snippet;
		error?: string;
		class?: string;
		children: Snippet;
	} = $props();

	const ctx = fieldCtx();
	const st = $derived(ctx?.state(path) ?? { kind: 'defined' as const });
	const what = $derived(name ?? label ?? fieldLabel(path));
</script>

{#snippet source()}
	{#if st.kind === 'inherited'}
		<span class="text-muted inline-flex shrink-0 items-center gap-1 text-xs whitespace-nowrap" title="Inherited from {st.from?.name ?? 'a set above'}">
			<CornerLeftUp class="size-3.5" aria-hidden="true" /><span class="sr-only">Inherited from</span><span class="max-w-48 truncate">{st.from?.name ?? 'a set above'}</span>
		</span>
	{:else if st.kind === 'overridden'}
		<span class="inline-flex shrink-0 items-center gap-1.5 text-xs whitespace-nowrap">
			<span class="text-info inline-flex items-center gap-1 font-medium"><PencilLine class="size-3.5" aria-hidden="true" />{st.saved ? 'Overridden' : 'Changed'}</span>
			{#if ctx?.canReset}
				<button type="button" class="text-muted hover:text-fg hover:bg-hover inline-flex h-6 items-center gap-1 rounded px-1.5 font-medium" aria-label="Reset {what} to inherited" title="Use the inherited value again" onclick={() => ctx.reset(path)}>
					<RotateCcw class="size-3" aria-hidden="true" />Reset
				</button>
			{/if}
		</span>
	{/if}
{/snippet}

<div class={cx(klass, st.kind === 'overridden' && 'border-info bg-info-soft/50 -mx-2 rounded-r-md border-l-2 py-1.5 pr-2 pl-2', st.kind === 'overridden' && !st.saved && 'border-dashed')} data-source={st.kind}>
	{#if label}
		<div class="mb-1.5 flex flex-wrap items-center justify-between gap-x-3 gap-y-0.5">
			<label class="label mb-0" for={id}>{label}</label>
			{@render source()}
		</div>
		{@render children()}
	{:else}
		<!-- The source above the control on phones, beside it from sm. -->
		<div class="flex flex-col-reverse gap-1 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start sm:gap-x-3">
			<div class="min-w-0">{@render children()}</div>
			{#if st.kind !== 'defined'}<div class="sm:pt-0.5">{@render source()}</div>{/if}
		</div>
	{/if}
	{#if error}
		<p class="text-danger mt-1 text-xs" role="alert">{error}</p>
	{:else if hint}
		<p class={cx('hint', !label && 'ml-11.5')}>{#if typeof hint === 'string'}{hint}{:else}{@render hint()}{/if}</p>
	{/if}
</div>
