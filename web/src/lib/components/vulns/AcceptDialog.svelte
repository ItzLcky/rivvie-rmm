<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Accepts the risk of a CVE for one device, or every device of a client, for a while. */
	let {
		vulnId,
		clients,
		agent = null,
		onclose,
		ondone
	}: {
		vulnId: string;
		/** The clients that have it (the first is chosen). */
		clients: { id: string; name: string }[];
		/** Just this device. */
		agent?: { id: string; hostname: string; client_id: string } | null;
		onclose: () => void;
		ondone: () => void;
	} = $props();

	const initial = untrack(() => ({ client: agent?.client_id ?? clients[0]?.id ?? '', scope: (agent ? 'agent' : 'client') as 'agent' | 'client' }));
	let clientId = $state(initial.client);
	let scope = $state(initial.scope);
	let days = $state('90');
	let note = $state('');
	let busy = $state(false);

	async function save() {
		busy = true;
		const expires_at = days === 'never' ? null : new Date(Date.now() + Number(days) * 86_400_000).toISOString();
		const ok = await attempt(
			() => api.post('/vulnerabilities/acceptances', { vuln_id: vulnId, client_id: clientId, agent_id: scope === 'agent' ? agent?.id : null, note, expires_at }),
			'Risk accepted.'
		);
		busy = false;
		if (ok) ondone();
	}
</script>

<Modal title="Accept the risk of {vulnId}" description="Accepted findings stop counting towards alerts and totals until the acceptance expires." {onclose}>
	<div class="space-y-4">
		{#if agent}
			<Field label="For" id="va-scope">
				<Select id="va-scope" bind:value={scope} options={[{ value: 'agent', label: agent.hostname }, { value: 'client', label: 'Every device of its client' }]} />
			</Field>
		{:else}
			<Field label="Client" id="va-client" hint="Every device of the client, now and later.">
				<Select id="va-client" bind:value={clientId} options={clients.map((c) => ({ value: c.id, label: c.name }))} />
			</Field>
		{/if}
		<Field label="Until" id="va-days">
			<Select id="va-days" bind:value={days} options={[{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '180', label: '6 months' }, { value: '365', label: 'A year' }, { value: 'never', label: 'Until removed' }]} />
		</Field>
		<Field label="Why" id="va-note" hint="Compensating controls, a planned upgrade, the system owner's decision.">
			<Textarea id="va-note" rows={3} maxlength={2000} bind:value={note} />
		</Field>
	</div>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" loading={busy} disabled={!clientId} onclick={save}>Accept risk</Button>
	{/snippet}
</Modal>
