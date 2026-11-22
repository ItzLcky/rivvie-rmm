<script lang="ts">
	import { BookOpen, Plus, ServerCog, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import ApiKeys from '#lib/components/ApiKeys.svelte';
	import ClientAccess from '#lib/components/ClientAccess.svelte';
	import { clients } from '#lib/scope.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	interface Account { id: string; name: string; role: string; disabled: boolean; all_clients: boolean; client_ids: string[]; keys: number; created_at: string }
	const accounts = resource(() => api.get<Account[]>('/service-accounts'));
	// The keys list reloads when accounts do, so a removed account's keys show as revoked.
	let gen = $state(0);

	const blank = () => ({ name: '', role: 'technician', all_clients: false, client_ids: [] as string[] });
	let adding = $state(false);
	let form = $state(blank());
	let busy = $state(false);
	async function add(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		const ok = await attempt(() => api.post('/service-accounts', form), `${form.name} added.`);
		busy = false;
		if (ok) {
			adding = false;
			form = blank();
			accounts.reload();
		}
	}
	async function remove(a: Account) {
		const ok = await confirmAction({
			title: `Remove ${a.name}?`,
			message: `Its ${a.keys} active key${a.keys === 1 ? '' : 's'} stop${a.keys === 1 ? 's' : ''} working at once.`,
			confirmLabel: 'Remove account',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/service-accounts/${a.id}`), `${a.name} removed.`))) {
			accounts.reload();
			gen++;
		}
	}
	const reach = (a: Account) =>
		a.all_clients ? 'All clients' : a.client_ids.length ? clients.list.filter((c) => a.client_ids.includes(c.id)).map((c) => c.name).join(', ') : 'No clients';
</script>

<div class="max-w-5xl space-y-5">
	<div class="card flex flex-wrap items-center gap-3 p-4 text-sm">
		<BookOpen class="text-muted size-5 shrink-0" aria-hidden="true" />
		<p class="min-w-0 flex-1">
			The public REST API lives at <code class="text-fg">/api/v1</code> and is described by an OpenAPI 3.1 document at <a class="link" href="/api/openapi.json">/api/openapi.json</a>.
		</p>
		<Button href="/developers">API reference</Button>
	</div>

	<section class="card" aria-labelledby="sa-h">
		<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="sa-h" class="font-semibold">Service accounts</h2>
				<p class="text-muted text-xs">Accounts for other systems. They can’t sign in; their keys act as them, within their role and clients.</p>
			</div>
			<Button icon={Plus} onclick={() => (adding = true)}>Add service account</Button>
		</header>
		<Async res={accounts} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as a (a.id)}
							<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">
								<ServerCog class="text-muted size-4 shrink-0" aria-hidden="true" />
								<div class="min-w-0 flex-1">
									<div class="font-medium">{a.name} {#if a.disabled}<Badge>Removed</Badge>{/if}</div>
									<div class="text-muted truncate text-xs">{a.role === 'readonly' ? 'Read-only' : 'Technician'} · {reach(a)} · {a.keys} active key{a.keys === 1 ? '' : 's'}</div>
								</div>
								{#if !a.disabled}<IconButton icon={Trash2} size="sm" label="Remove {a.name}" onclick={() => remove(a)} />{/if}
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={ServerCog} title="No service accounts" description="Add one for a system that shouldn’t act as a person, then create its keys below." />
				{/if}
			{/snippet}
		</Async>
	</section>

	{#key gen}
		<ApiKeys all accounts={accounts.data ?? []} />
	{/key}
</div>

{#if adding}
	<Modal title="Add service account" onclose={() => (adding = false)}>
		<form id="sa-form" class="space-y-4" onsubmit={add}>
			<Field label="Name" id="sa-name" hint="The system it is for, e.g. “Reporting pipeline”." required><Input id="sa-name" bind:value={form.name} required maxlength={100} /></Field>
			<Field label="Role" id="sa-role" hint="Fine-tune permissions on its user afterwards (Users).">
				<Select id="sa-role" bind:value={form.role} options={[{ value: 'technician', label: 'Technician' }, { value: 'readonly', label: 'Read-only' }]} />
			</Field>
			<div>
				<div class="label">Clients</div>
				<ClientAccess clients={clients.list} bind:value={form} />
			</div>
		</form>
		{#snippet footer()}
			<Button onclick={() => (adding = false)}>Cancel</Button>
			<Button variant="primary" type="submit" form="sa-form" loading={busy}>Add account</Button>
		{/snippet}
	</Modal>
{/if}
