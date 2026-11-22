<script lang="ts">
	import { api } from '#lib/api.js';
	import { kindOptions, type Credential, type DeviceKind, type NetDevice } from '#lib/network.js';
	import { clients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import { resource } from '#lib/resource.svelte.js';

	/** Add a device to read over SNMP by address, or change one. */
	let { device = null, siteId = '', onclose, ondone }: { device?: NetDevice | null; siteId?: string; onclose: () => void; ondone: (id?: string) => void } = $props();

	// svelte-ignore state_referenced_locally
	const d = device;
	const sites = $derived(clients.list.flatMap((c) => c.sites.map((s) => ({ value: s.id, label: `${c.name} › ${s.name}`, client: c.id }))));
	// svelte-ignore state_referenced_locally
	let site = $state(d?.site_id ?? siteId);
	// svelte-ignore state_referenced_locally
	let name = $state(d?.name ?? '');
	// svelte-ignore state_referenced_locally
	let host = $state(d?.host ?? '');
	// svelte-ignore state_referenced_locally
	let port = $state(d?.port ?? 161);
	let kind = $state<DeviceKind>(d?.kind ?? 'other');
	let credential = $state(d?.credential_id ?? '');
	let poll = $state(d?.poll_secs ?? 0);
	let saving = $state(false);

	const clientOf = $derived(d?.client_id ?? sites.find((s) => s.value === site)?.client ?? '');
	const creds = resource(() => (clientOf ? api.get<Credential[]>(`/clients/${clientOf}/network-credentials`) : Promise.resolve([] as Credential[])));
	$effect(() => {
		clientOf;
		creds.reload();
	});
	$effect(() => {
		if (creds.data && !creds.data.some((c) => c.id === credential)) credential = creds.data[0]?.id ?? '';
	});

	async function save(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		try {
			const body = { name, host, port: Number(port), kind, credential_id: credential, poll_secs: Number(poll) };
			if (d) {
				await api.put(`/network/devices/${d.id}`, body);
				toast.success(`${name} saved.`);
				ondone();
			} else {
				const r = await api.post<{ id: string }>('/network/devices', { ...body, site_id: site });
				toast.success(`${name} added; it is read within a minute.`);
				ondone(r.id);
			}
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
</script>

<Modal title={d ? `Edit ${d.name}` : 'Add a network device'} description="Read over SNMP by the site's designated agent. The address has to be on a private network." {onclose}>
	<form id="dev-form" class="space-y-4" onsubmit={save}>
		{#if !d}
			<Field label="Site" id="dv-site" required hint="The site's designated agent reads it.">
				<Select id="dv-site" class="w-full" required bind:value={site} options={[{ value: '', label: 'Choose a site…', disabled: true }, ...sites]} />
			</Field>
		{/if}
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Name" id="dv-name" required><Input id="dv-name" required maxlength={100} bind:value={name} placeholder="Core switch" /></Field>
			<Field label="Kind" id="dv-kind"><Select id="dv-kind" class="w-full" bind:value={kind} options={kindOptions} /></Field>
			<Field label="Address" id="dv-host" required hint="An IP address, e.g. 192.168.1.2."><Input id="dv-host" required class="font-mono" bind:value={host} placeholder="192.168.1.2" /></Field>
			<Field label="SNMP port" id="dv-port"><Input id="dv-port" type="number" min="1" max="65535" bind:value={port} /></Field>
		</div>
		<Field label="Credentials" id="dv-cred" required hint={creds.data && !creds.data.length ? 'This client has none yet: add them under Network → Settings.' : undefined}>
			<Select id="dv-cred" class="w-full" required bind:value={credential} options={(creds.data ?? []).map((c) => ({ value: c.id, label: `${c.name} (${c.version})` }))} />
		</Field>
		<Field label="Read every (seconds)" id="dv-poll" hint="0 uses the site's interval. 60 to 3600.">
			<Input id="dv-poll" type="number" min="0" max="3600" class="max-w-40" bind:value={poll} />
		</Field>
	</form>
	{#snippet footer()}
		<Button variant="ghost" onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="dev-form" loading={saving} disabled={!credential}>{d ? 'Save' : 'Add device'}</Button>
	{/snippet}
</Modal>
