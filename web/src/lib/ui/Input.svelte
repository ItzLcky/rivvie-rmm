<script lang="ts">
	import type { Component } from 'svelte';
	import type { HTMLInputAttributes } from 'svelte/elements';
	import { cx } from '#lib/format.js';

	type Props = HTMLInputAttributes & { icon?: Component<{ class?: string }>; ref?: HTMLInputElement | null; invalid?: boolean };
	let { value = $bindable(), icon: Icon, class: klass, ref = $bindable(null), invalid = false, ...rest }: Props = $props();
</script>

{#if Icon}
	<div class={cx('relative', klass as string)}>
		<Icon class="text-subtle pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
		<input bind:this={ref} bind:value class="control pl-8" aria-invalid={invalid || undefined} {...rest} />
	</div>
{:else}
	<input bind:this={ref} bind:value class={cx('control', klass as string)} aria-invalid={invalid || undefined} {...rest} />
{/if}
