<script lang="ts">
	import { api } from '#lib/api.js';
	import { kindOptions, type Credential, type DeviceKind, type Discovered } from '#lib/network.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	/** Start reading a discovered host over SNMP. */
	let { host, onclose, ondone }: { host: Discovered; onclose: () => void; ondone: (deviceId: string) => void } = $props();

	// svelte-ignore state_referenced_locally
	let name = $state(host.sys_name ?? host.hostname ?? host.ip);
	// svelte-ignore state_referenced_locally
	let kind = $state<DeviceKind>(host.kind);
	// svelte-ignore state_referenced_locally
	let credential = $state(host.credential_id ?? '');
	let saving = $state(false);
	const creds = resource(() => api.get<Credential[]>(`/clients/${host.client_id}/network-credentials`));
	$effect(() => {
		if (creds.data && !creds.data.some((c) => c.id === credential)) credential = creds.data[0]?.id ?? '';
	});

	async function save(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		try {
			const r = await api.post<{ id: string }>(`/network/discovered/${host.id}/monitor`, { name, kind, credential_id: credential });
			toast.success(`${name} is now monitored.`);
			ondone(r.id);
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
</script>

<Modal title="Monitor {host.ip}" description={host.sys_descr ?? host.vendor ?? 'Read it over SNMP from now on.'} {onclose}>
	<form id="mon-form" class="space-y-4" onsubmit={save}>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Name" id="mo-name" required><Input id="mo-name" required maxlength={100} bind:value={name} /></Field>
			<Field label="Kind" id="mo-kind"><Select id="mo-kind" class="w-full" bind:value={kind} options={kindOptions} /></Field>
		</div>
		<Field
			label="Credentials"
			id="mo-cred"
			required
			hint={host.credential_id ? 'The set that answered the scan is chosen.' : creds.data && !creds.data.length ? 'This client has no SNMP credentials yet: add them under Network → Settings.' : 'No credentials answered the scan; pick the ones the device is set up with.'}
		>
			<Select id="mo-cred" class="w-full" required bind:value={credential} options={(creds.data ?? []).map((c) => ({ value: c.id, label: `${c.name} (${c.version})` }))} />
		</Field>
	</form>
	{#snippet footer()}
		<Button variant="ghost" onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="mon-form" loading={saving} disabled={!credential}>Start monitoring</Button>
	{/snippet}
</Modal>
