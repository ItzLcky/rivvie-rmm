<script lang="ts">
	import CopyButton from './CopyButton.svelte';
	import { cx } from '#lib/format.js';

	/** Preformatted text (install commands, tokens) with a copy button. */
	let { code, label, class: klass = '' }: { code: string; label?: string; class?: string } = $props();
</script>

<div class={klass}>
	{#if label}<div class="label">{label}</div>{/if}
	<div class="group relative">
		<pre class="code-block pr-10 whitespace-pre-wrap break-all select-all">{code}</pre>
		<div class="absolute top-1.5 right-1.5"><CopyButton text={code} label="Copy {label ?? 'to clipboard'}" /></div>
	</div>
</div>
