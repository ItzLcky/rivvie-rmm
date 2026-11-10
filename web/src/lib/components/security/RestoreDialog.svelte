<script lang="ts">
	import { api } from '#lib/api.js';
	import { allowed } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Modal from '#lib/ui/Modal.svelte';

	/** Restores one quarantined file to where it was, optionally excluding its hash for the client. */
	let {
		agentId,
		hostname,
		id,
		path,
		detectionId,
		onclose,
		ondone
	}: { agentId: string; hostname: string; id: string; path: string; detectionId?: string; onclose: () => void; ondone?: () => void } = $props();

	let exclude = $state(false);
	let busy = $state(false);
	const canExclude = $derived(allowed('security.manage'));

	async function submit() {
		busy = true;
		try {
			await api.post(`/agents/${agentId}/security/respond`, { action: { type: 'restore_file', id }, detection_id: detectionId ?? null, exclude_hash: exclude && canExclude });
			toast.success(`Restore sent to ${hostname}.${exclude ? ' The file’s hash is excluded for this client.' : ''}`);
			ondone?.();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Restore this file?" {onclose} size="md">
	<div class="space-y-3 text-sm">
		<p>The agent puts the file back where it was and it can run again:</p>
		<p class="border-border bg-sunken rounded-md border px-3 py-2 font-mono text-xs break-all">{path}</p>
		<p class="text-muted">Only restore files you’re sure are safe. Without an exclusion, the next scan may quarantine it again.</p>
		{#if canExclude}
			<Checkbox bind:checked={exclude}>Also exclude this file’s hash for this client</Checkbox>
		{/if}
	</div>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" loading={busy} onclick={submit}>Restore file</Button>
	{/snippet}
</Modal>
