<script lang="ts">
	import { api } from '#lib/api.js';
	import type { Credential } from '#lib/network.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';

	/** SNMP credentials of one client. Secrets are write-only: when editing, a blank one stays as it is. */
	let { clientId, credential = null, onclose, ondone }: { clientId: string; credential?: Credential | null; onclose: () => void; ondone: () => void } = $props();

	// svelte-ignore state_referenced_locally
	const c = credential;
	let name = $state(c?.name ?? '');
	let version = $state<'v2c' | 'v3'>(c?.version ?? 'v2c');
	let community = $state('');
	let username = $state(c?.username ?? '');
	let authProto = $state(c?.auth_proto ?? '');
	let authSecret = $state('');
	let privProto = $state(c?.priv_proto ?? '');
	let privSecret = $state('');
	let context = $state(c?.context ?? '');
	let saving = $state(false);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		try {
			const body: Record<string, unknown> = { name };
			if (!c) body.version = version;
			if (version === 'v2c') {
				if (community || !c) body.community = community;
			} else {
				Object.assign(body, { username, context, auth_proto: authProto, priv_proto: authProto ? privProto : '' });
				if (authSecret) body.auth_secret = authSecret;
				if (privSecret && authProto && privProto) body.priv_secret = privSecret;
			}
			if (c) await api.put(`/network-credentials/${c.id}`, body);
			else await api.post(`/clients/${clientId}/network-credentials`, body);
			toast.success(`${name} saved.`);
			ondone();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = false;
		}
	}
</script>

<Modal title={c ? `Edit ${c.name}` : 'New SNMP credentials'} description="Kept sealed on the server and sent to the site's agent only when it scans or reads a device. Nothing shows them again." {onclose}>
	<form id="cred-form" class="space-y-4" onsubmit={save}>
		<Field label="Name" id="cr-name" required><Input id="cr-name" required maxlength={100} bind:value={name} placeholder="Switches (read-only)" /></Field>
		{#if !c}
			<div class="space-y-1.5">
				<span class="label">Version</span>
				<Segmented label="SNMP version" size="md" value={version} onchange={(v) => (version = v)} options={[{ value: 'v2c', label: 'v2c (community)' }, { value: 'v3', label: 'v3 (user)' }]} />
			</div>
		{:else}
			<p class="text-muted text-sm">SNMP {c.version}. The version can't be changed; make new credentials for a different one.</p>
		{/if}
		{#if version === 'v2c'}
			<Field label="Community string" id="cr-comm" required={!c} hint={c ? 'Leave blank to keep the current one.' : 'Use a read-only community.'}>
				<Input id="cr-comm" type="password" autocomplete="off" required={!c} bind:value={community} placeholder={c ? '••••••••' : ''} />
			</Field>
		{:else}
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="User name" id="cr-user" required><Input id="cr-user" required maxlength={32} autocomplete="off" bind:value={username} /></Field>
				<Field label="Context" id="cr-ctx" hint="Usually empty."><Input id="cr-ctx" maxlength={64} bind:value={context} /></Field>
			</div>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Authentication" id="cr-auth">
					<Select id="cr-auth" class="w-full" bind:value={authProto} options={[{ value: '', label: 'None' }, ...['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].map((p) => ({ value: p, label: p.toUpperCase() }))]} />
				</Field>
				<Field label="Authentication passphrase" id="cr-asec" hint={c && authProto ? 'Blank keeps the current one. 8 characters or more.' : '8 characters or more.'}>
					<Input id="cr-asec" type="password" autocomplete="off" minlength={8} disabled={!authProto} required={!!authProto && !c?.auth_proto} bind:value={authSecret} />
				</Field>
				<Field label="Privacy (encryption)" id="cr-priv">
					<Select id="cr-priv" class="w-full" disabled={!authProto} bind:value={privProto} options={[{ value: '', label: 'None' }, { value: 'aes128', label: 'AES-128' }, { value: 'des', label: 'DES' }]} />
				</Field>
				<Field label="Privacy passphrase" id="cr-psec" hint={c && privProto ? 'Blank keeps the current one.' : undefined}>
					<Input id="cr-psec" type="password" autocomplete="off" minlength={8} disabled={!authProto || !privProto} required={!!privProto && !c?.priv_proto} bind:value={privSecret} />
				</Field>
			</div>
		{/if}
	</form>
	{#snippet footer()}
		<Button variant="ghost" onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="cred-form" loading={saving}>Save</Button>
	{/snippet}
</Modal>
