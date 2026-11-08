<script lang="ts">
	import type { Snippet } from 'svelte';

	/** A labelled form row: label, the control (with `id`), a hint and an error. */
	let {
		label,
		id,
		hint,
		error,
		required = false,
		class: klass = '',
		children
	}: { label: string; id?: string; hint?: string | Snippet; error?: string; required?: boolean; class?: string; children: Snippet } = $props();
</script>

<div class={klass}>
	<label class="label" for={id}>{label}{#if required}<span class="text-danger" aria-hidden="true"> *</span>{/if}</label>
	{@render children()}
	{#if error}
		<p class="text-danger mt-1 text-xs" role="alert">{error}</p>
	{:else if hint}
		<p class="hint">{#if typeof hint === 'string'}{hint}{:else}{@render hint()}{/if}</p>
	{/if}
</div>
