<script lang="ts">
	import type { HTMLTextareaAttributes } from 'svelte/elements';
	import { cx } from '#lib/format.js';

	let { value = $bindable(), class: klass, ...rest }: HTMLTextareaAttributes = $props();
</script>

<textarea bind:value class={cx('control', klass as string)} {...rest}></textarea>
