<script lang="ts">
	import { Check, Copy } from '@lucide/svelte';
	import IconButton from './IconButton.svelte';

	let { text, label = 'Copy' }: { text: string; label?: string } = $props();
	let done = $state(false);
	async function copy() {
		try {
			await navigator.clipboard.writeText(text);
			done = true;
			setTimeout(() => (done = false), 1500);
		} catch {
			/* clipboard blocked (http, permissions): the text is selectable */
		}
	}
</script>

<IconButton icon={done ? Check : Copy} label={done ? 'Copied' : label} size="sm" onclick={copy} />
