<script lang="ts">
	import { api } from '#lib/api.js';
	import { clients } from '#lib/scope.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { Contact } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Adds a contact to `clientId`, or edits `contact`. */
	let { contact, clientId, onclose, onsaved }: { contact: Contact | null; clientId: string; onclose: () => void; onsaved: (c: Contact) => void } = $props();

	// svelte-ignore state_referenced_locally
	const c = contact;
	let f = $state({
		name: c?.name ?? '',
		email: c?.email ?? '',
		phone: c?.phone ?? '',
		job_title: c?.job_title ?? '',
		site_id: c?.site_id ?? '',
		notes: c?.notes ?? '',
		is_primary: c?.is_primary ?? false,
		portal_enabled: c?.portal_enabled ?? false,
		portal_all_tickets: c?.portal_all_tickets ?? false,
		is_billing: c?.is_billing ?? false
	});
	let invite = $state(!c);
	let busy = $state(false);
	// svelte-ignore state_referenced_locally
	const sites = $derived(clients.list.find((x) => x.id === clientId)?.sites ?? []);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const body = { ...f, client_id: clientId, site_id: f.site_id || null };
			const saved = c ? await api.put<Contact>(`/contacts/${c.id}`, body) : await api.post<Contact>('/contacts', body);
			const newlyEnabled = saved.portal_enabled && (!c?.portal_enabled || c.email !== saved.email);
			if (newlyEnabled && invite) {
				await api.post(`/contacts/${saved.id}/portal-invite`);
				toast.success(`${saved.name} saved and invited to the portal.`);
			} else toast.success(`${saved.name} saved.`);
			onsaved(saved);
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title={c ? `Edit ${c.name}` : 'Add contact'} {onclose}>
	<form id="contact-form" class="space-y-4" onsubmit={save}>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Name" id="ct-name" required>
				<!-- svelte-ignore a11y_autofocus -->
				<Input id="ct-name" bind:value={f.name} required maxlength={200} autofocus autocomplete="off" />
			</Field>
			<Field label="Job title" id="ct-title"><Input id="ct-title" bind:value={f.job_title} maxlength={200} autocomplete="off" /></Field>
		</div>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Email" id="ct-email" hint="Their mail is filed on their tickets; replies go here."><Input id="ct-email" type="email" bind:value={f.email} autocomplete="off" /></Field>
			<Field label="Phone" id="ct-phone"><Input id="ct-phone" type="tel" bind:value={f.phone} maxlength={50} autocomplete="off" /></Field>
		</div>
		{#if sites.length > 1}
			<Field label="Site" id="ct-site">
				<Select id="ct-site" class="w-full" bind:value={f.site_id} options={[{ value: '', label: 'Any site' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]} />
			</Field>
		{/if}
		<Field label="Notes" id="ct-notes"><Textarea id="ct-notes" rows={3} bind:value={f.notes} /></Field>
		<Switch bind:checked={f.is_primary}>Primary contact (preselected on new tickets)</Switch>
		<Switch bind:checked={f.is_billing}>Billing contact (invoices are emailed to them, and shown in their portal)</Switch>
		<fieldset class="border-border space-y-2 border-t pt-3">
			<legend class="sr-only">Client portal</legend>
			<Switch bind:checked={f.portal_enabled} disabled={!f.email.trim()}>Client portal access{#if !f.email.trim()}<span class="text-muted"> (needs an email)</span>{/if}</Switch>
			{#if f.portal_enabled}
				<div class="space-y-2 pl-11.5">
					<Switch bind:checked={f.portal_all_tickets} disabled={f.is_primary}>Sees every ticket of the client{#if f.is_primary}<span class="text-muted"> (primary contacts always do)</span>{/if}</Switch>
					{#if !c?.portal_enabled || c.email !== f.email.trim().toLowerCase()}
						<Switch bind:checked={invite}>Email an invitation when saved</Switch>
					{/if}
				</div>
			{/if}
		</fieldset>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="contact-form" loading={busy} disabled={!f.name.trim()}>Save</Button>
	{/snippet}
</Modal>
