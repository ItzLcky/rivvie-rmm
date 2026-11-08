<script lang="ts" generics="V extends string | number | null">
	import type { HTMLSelectAttributes } from 'svelte/elements';
	import { cx } from '#lib/format.js';

	/** A native select (accessible, and the right picker on phones) styled like the other controls. */
	type Props = Omit<HTMLSelectAttributes, 'value'> & {
		value: V;
		options: { value: V; label: string; disabled?: boolean }[];
	};
	let { value = $bindable(), options, class: klass, ...rest }: Props = $props();
</script>

<select bind:value class={cx('control', klass as string)} {...rest}>
	{#each options as o (o.value)}<option value={o.value} disabled={o.disabled}>{o.label}</option>{/each}
</select>
