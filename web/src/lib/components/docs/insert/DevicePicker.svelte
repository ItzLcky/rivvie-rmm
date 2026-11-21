<script lang="ts">
	import { Monitor } from '@lucide/svelte';
	import { fence } from '#lib/docs/markdown.js';
	import type { AgentSummary } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	/** Insert block → Device: one of the client's devices. */
	let { agents, oninsert, onclose }: { agents: () => Promise<Map<string, AgentSummary>>; oninsert: (md: string) => void; onclose: () => void } = $props();
	let list = $state<AgentSummary[] | null>(null);
	let error = $state<Error | null>(null);
	let value = $state('');
	const load = () =>
		agents().then(
			(m) => (list = [...m.values()].sort((a, b) => a.hostname.localeCompare(b.hostname))),
			(e) => (error = e instanceof Error ? e : new Error(String(e)))
		);
	load();
	function submit(e: SubmitEvent) {
		e.preventDefault();
		if (value) oninsert(fence('device', `agent: ${value}`));
	}
</script>

<Modal title="Insert a device" description="The page shows its name, whether it’s online and its OS, and links to it." {onclose} size="md">
	{#if error}
		<ErrorState {error} compact onretry={() => ((error = null), load())} />
	{:else if !list}
		<div aria-busy="true" class="space-y-2"><span class="sr-only">Loading devices</span><Skeleton class="h-4 w-24" /><Skeleton class="h-9 w-full" /></div>
	{:else if !list.length}
		<EmptyState compact icon={Monitor} title="No devices yet" description="Enroll the client’s machines first; then they can be linked from a page." />
	{:else}
		<form id="device-form" onsubmit={submit}>
			<Field label="Device" id="device-pick">
				<Combobox id="device-pick" bind:value items={list.map((a) => ({ value: a.id, label: a.hostname, hint: `${a.site_name} · ${a.online ? 'online' : 'offline'}` }))} placeholder="Search by host name" />
			</Field>
		</form>
	{/if}
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="device-form" disabled={!value}>Insert</Button>
	{/snippet}
</Modal>
