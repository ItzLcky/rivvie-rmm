<script lang="ts">
	import { fence } from '#lib/docs/markdown.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';

	/** Insert block → Credential in a template: an empty slot that pages fill from the vault. */
	let { oninsert, onclose }: { oninsert: (md: string) => void; onclose: () => void } = $props();
	let label = $state('');
	function submit(e: SubmitEvent) {
		e.preventDefault();
		oninsert(fence('credential', `label: ${label.trim() || 'Credential'}`));
	}
</script>

<Modal title="Insert a credential slot" description="Templates have no vault: a page started from this one shows a Choose credential button here." {onclose} size="sm">
	<form id="slot-form" onsubmit={submit}>
		<Field label="Label" id="slot-label" hint="What goes here, e.g. Firewall admin.">
			<!-- svelte-ignore a11y_autofocus -->
			<Input id="slot-label" bind:value={label} maxlength={200} autofocus />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="slot-form">Insert</Button>
	{/snippet}
</Modal>
