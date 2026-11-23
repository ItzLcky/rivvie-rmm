<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { can } from '#lib/session.svelte.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { SoftwarePackage } from '#lib/software.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/**
	 * A catalog package: where it comes from on each platform, and the version it's held at.
	 * `pkg` null creates one. The uploaded installer is handled on the package's page.
	 */
	let { pkg = null, ondone, oncancel }: { pkg?: SoftwarePackage | null; ondone: (p: SoftwarePackage) => void; oncancel?: () => void } = $props();

	const p0 = untrack(() => pkg);
	let f = $state({
		client_id: (p0?.client_id ?? (can('admin') ? null : '')) as string | null,
		name: p0?.name ?? '',
		description: p0?.description ?? '',
		publisher: p0?.publisher ?? '',
		winget_id: p0?.winget_id ?? '',
		choco_id: p0?.choco_id ?? '',
		apt_name: p0?.apt_name ?? '',
		dnf_name: p0?.dnf_name ?? '',
		version: p0?.version ?? '',
		silent_args: p0?.silent_args ?? '',
		uninstall_cmd: p0?.uninstall_cmd ?? '',
		product_code: p0?.product_code ?? '',
		detect_name: p0?.detect_name ?? ''
	});
	let busy = $state(false);
	$effect(() => {
		untrack(() => loadClients());
	});
	$effect(() => {
		// A technician can't make MSP-wide packages: start with their first client.
		if (!pkg && f.client_id === '' && clients.list.length) untrack(() => (f.client_id = clients.list[0].id));
	});
	const hasInstaller = !!p0?.installer;
	const idPattern = '[A-Za-z0-9._+:~\\-]+';

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const body = { ...f, client_id: f.client_id || null };
			const r = pkg ? await api.put<SoftwarePackage>(`/software/packages/${pkg.id}`, body) : await api.post<SoftwarePackage>('/software/packages', body);
			toast.success(pkg ? 'Saved.' : `${r.name} added to the catalog.`);
			ondone(r);
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<form class="space-y-4" onsubmit={save} aria-label={pkg ? 'Edit package' : 'New package'}>
	<div class="grid gap-3 sm:grid-cols-2">
		<Field label="Name" id="pk-name" required><Input id="pk-name" bind:value={f.name} required maxlength={200} placeholder="e.g. Mozilla Firefox" /></Field>
		<Field label="Publisher" id="pk-pub"><Input id="pk-pub" bind:value={f.publisher} maxlength={200} /></Field>
	</div>
	{#if !pkg}
		<Field label="Available to" id="pk-client" hint="MSP-wide packages can be used by every client; a client’s own only on its devices.">
			<Select id="pk-client" class="w-full sm:w-72" bind:value={f.client_id} options={[...(can('admin') ? [{ value: null, label: 'Every client (MSP-wide)' }] : []), ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
		</Field>
	{/if}
	<Field label="Description" id="pk-desc"><Textarea id="pk-desc" rows={2} bind:value={f.description} /></Field>

	<fieldset class="border-border space-y-3 rounded-md border p-3">
		<legend class="px-1 text-sm font-semibold">Where it comes from</legend>
		<p class="text-muted text-xs">Fill in the ones that apply. A device uses the first it can: winget, Chocolatey, then an uploaded installer on Windows; apt, then dnf on Linux.</p>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="winget id" id="pk-winget" hint="Mozilla.Firefox"><Input id="pk-winget" class="font-mono" bind:value={f.winget_id} pattern={idPattern} /></Field>
			<Field label="Chocolatey id" id="pk-choco" hint="firefox"><Input id="pk-choco" class="font-mono" bind:value={f.choco_id} pattern={idPattern} /></Field>
			<Field label="apt package" id="pk-apt" hint="firefox"><Input id="pk-apt" class="font-mono" bind:value={f.apt_name} pattern={idPattern} /></Field>
			<Field label="dnf package" id="pk-dnf" hint="firefox"><Input id="pk-dnf" class="font-mono" bind:value={f.dnf_name} pattern={idPattern} /></Field>
		</div>
	</fieldset>

	<Field label="Version" id="pk-version" hint={hasInstaller ? 'The version the uploaded installer installs. Required.' : 'Empty: install and keep the latest. A version holds devices at it (older ones are brought up to it; newer ones are left alone).'}>
		<Input id="pk-version" class="w-full font-mono sm:w-60" bind:value={f.version} pattern={idPattern} required={hasInstaller} placeholder="Latest" />
	</Field>

	{#if pkg}
		<fieldset class="border-border space-y-3 rounded-md border p-3">
			<legend class="px-1 text-sm font-semibold">Uploaded installer</legend>
			<Field label="Silent install arguments" id="pk-args" hint={'Passed to the installer, split on spaces (double quotes group). An MSI already gets /qn /norestart. An EXE needs its own, like /S or /VERYSILENT.'}>
				<Input id="pk-args" class="font-mono" bind:value={f.silent_args} placeholder="/S" />
			</Field>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Product code" id="pk-code" hint="MSI: {'{GUID}'}. Detects it and removes it."><Input id="pk-code" class="font-mono" bind:value={f.product_code} placeholder={'{00000000-0000-0000-0000-000000000000}'} /></Field>
				<Field label="Detect by name" id="pk-detect" hint="Its name under Apps & features, when there’s no product code."><Input id="pk-detect" bind:value={f.detect_name} /></Field>
			</div>
			<Field label="Uninstall command" id="pk-uninstall" hint="For an EXE: the command that removes it, with its silent switch."><Input id="pk-uninstall" class="font-mono" bind:value={f.uninstall_cmd} placeholder={'"C:\\Program Files\\App\\unins000.exe" /VERYSILENT'} /></Field>
		</fieldset>
	{/if}

	<div class="flex justify-end gap-2">
		{#if oncancel}<Button variant="ghost" onclick={oncancel}>Cancel</Button>{/if}
		<Button variant="primary" type="submit" loading={busy} disabled={!f.name.trim()}>{pkg ? 'Save' : 'Add package'}</Button>
	</div>
</form>
