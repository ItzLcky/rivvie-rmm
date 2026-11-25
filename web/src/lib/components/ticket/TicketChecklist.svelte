<script lang="ts">
	import { ListChecks, Pencil, Play, Plus, ShieldAlert, Trash2, UserRound } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { checklistActions, type Checklist, type ChecklistAction, type DirUser } from '#lib/identity.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Page } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import UserDrawer from '#lib/components/identity/UserDrawer.svelte';

	/**
	 * A ticket's checklist (from a template, or added here), the directory user it is about, and
	 * the directory accounts of the ticket's contact.
	 */
	let { ticketId, clientId, contactId, locked = false }: { ticketId: string; clientId: string | null; contactId: string | null; locked?: boolean } = $props();

	const list = resource(() => api.get<Checklist>(`/tickets/${ticketId}/checklist`));
	const readIdentity = $derived(allowed('identity.read') && !!clientId);
	const accounts = resource(() =>
		readIdentity && contactId ? api.get<Page<DirUser>>(`/clients/${clientId}/identity/users?contact_id=${contactId}&limit=20`).then((p) => p.items) : Promise.resolve([] as DirUser[])
	);
	$effect(() => {
		contactId;
		accounts.reload();
	});
	let clientUsers = $state<DirUser[] | null>(null);
	let editing = $state<{ id?: string; text: string; action: ChecklistAction | '' }[] | null>(null);
	let choosing = $state(false);
	let chosen = $state('');
	let running = $state<string | null>(null);
	let drawer = $state<string | null>(null);

	async function loadUsers() {
		choosing = true;
		if (!clientUsers && clientId) clientUsers = (await api.get<Page<DirUser>>(`/clients/${clientId}/identity/users?limit=500&sort=name`)).items;
		chosen = list.data?.identity_user?.id ?? '';
	}
	async function setUser() {
		if (await attempt(() => api.put(`/tickets/${ticketId}/checklist`, { items: (list.data?.items ?? []).map((i) => ({ id: i.id, text: i.text, action: i.action })), identity_user_id: chosen || null }), 'Directory user set.')) {
			choosing = false;
			list.reload();
		}
	}
	type EditItem = { id?: string; text: string; action: ChecklistAction | '' };
	function startEdit() {
		const items: EditItem[] = (list.data?.items ?? []).map((i) => ({ id: i.id, text: i.text, action: i.action ?? '' }));
		editing = items.length ? items : [{ text: '', action: '' }];
	}
	async function saveItems() {
		const items = editing!.filter((i) => i.text.trim()).map((i) => ({ id: i.id, text: i.text, action: i.action || null }));
		if (await attempt(() => api.put(`/tickets/${ticketId}/checklist`, { items }), 'Checklist saved.')) {
			editing = null;
			list.reload();
		}
	}
	async function tick(id: string, done: boolean) {
		await attempt(() => api.post(`/tickets/${ticketId}/checklist/${id}`, { done }));
		list.reload();
	}
	async function run(id: string, label: string) {
		running = id;
		try {
			const r = await api.post<Checklist>(`/tickets/${ticketId}/checklist/${id}/run`, {});
			toast.success(`${label}: done.`);
			list.set(r);
		} catch (e) {
			toast.error(e);
			list.reload();
		} finally {
			running = null;
		}
	}
	const actionLabel = (a: ChecklistAction | null) => checklistActions.find((x) => x.value === a)?.label ?? a ?? '';
	const progress = $derived(list.data ? list.data.items.filter((i) => i.done_at).length : 0);
</script>

<section class="card" aria-labelledby="cl-h">
	<header class="border-border flex min-h-12 items-center justify-between gap-2 border-b px-4 py-3">
		<h2 id="cl-h" class="panel-title">Checklist{#if list.data?.items.length}<span class="text-muted ml-1.5 font-normal">{progress}/{list.data.items.length}</span>{/if}</h2>
		{#if !locked && !editing && list.data}
			<IconButton icon={list.data.items.length ? Pencil : Plus} size="sm" label={list.data.items.length ? 'Edit the checklist' : 'Add a checklist'} onclick={startEdit} />
		{/if}
	</header>
	<div class="space-y-3 p-4">
		{#if readIdentity}
			<div class="text-sm">
				{#if choosing}
					<div class="flex gap-2">
						<Select aria-label="Directory user" class="min-w-0 flex-1" bind:value={chosen} options={[{ value: '', label: 'No directory user' }, ...(clientUsers ?? []).map((u) => ({ value: u.id, label: `${u.display_name || u.username} (${u.source_name})` }))]} />
						<Button size="sm" variant="primary" onclick={setUser}>Set</Button>
					</div>
				{:else if list.data?.identity_user}
					{@const iu = list.data.identity_user}
					<div class="flex items-center gap-2">
						<UserRound class="text-muted size-4 shrink-0" />
						<button class="hover:text-accent min-w-0 flex-1 truncate text-left font-medium" onclick={() => (drawer = iu.id)}>{iu.display_name || iu.username}</button>
						{#if iu.privileged}<Badge tone="warning"><ShieldAlert class="size-3" /> Privileged</Badge>{/if}
						{#if iu.enabled === false}<Badge>Disabled</Badge>{/if}
						{#if !locked}<Button size="sm" variant="ghost" onclick={loadUsers}>Change</Button>{/if}
					</div>
				{:else if !locked}
					<button class="link text-sm" onclick={loadUsers}>Choose the directory user this ticket is about</button>
				{/if}
			</div>
		{/if}

		{#if editing}
			<ul class="space-y-2">
				{#each editing as item, i (i)}
					<li class="space-y-1">
						<div class="flex gap-1.5">
							<Input aria-label="Item {i + 1}" class="min-w-0 flex-1" bind:value={item.text} maxlength={500} placeholder="What to do" />
							<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Remove item {i + 1}" onclick={() => editing!.splice(i, 1)} />
						</div>
						<Select aria-label="Action for item {i + 1}" class="w-full" bind:value={item.action} options={[{ value: '', label: 'Tick off by hand' }, ...checklistActions]} />
					</li>
				{/each}
			</ul>
			<div class="flex flex-wrap justify-between gap-2">
				<Button size="sm" variant="ghost" icon={Plus} onclick={() => editing!.push({ text: '', action: '' })}>Add item</Button>
				<div class="flex gap-2">
					<Button size="sm" onclick={() => (editing = null)}>Cancel</Button>
					<Button size="sm" variant="primary" onclick={saveItems}>Save</Button>
				</div>
			</div>
		{:else if list.data?.items.length}
			<ul class="space-y-2">
				{#each list.data.items as item (item.id)}
					{@const failed = item.action_state?.startsWith('failed')}
					<li class="text-sm">
						<div class="flex items-start gap-2">
							<Checkbox checked={!!item.done_at} disabled={locked || (!!item.action && !item.done_at)} onchange={(v: boolean) => tick(item.id, v)}><span class={item.done_at ? 'text-muted line-through' : ''}>{item.text}</span></Checkbox>
						</div>
						{#if item.action}
							<div class="ml-6 mt-1 flex flex-wrap items-center gap-2 text-xs">
								<span class="text-muted">{actionLabel(item.action)}</span>
								{#if item.action_state === 'done'}<Badge tone="success">Done</Badge>{:else if failed}<Badge tone="danger">Failed</Badge>{/if}
								{#if !item.done_at && !locked && allowed('identity.manage')}
									<Button size="sm" icon={Play} loading={running === item.id} disabled={!list.data.identity_user || !!running} title={list.data.identity_user ? undefined : 'Choose the directory user first'} onclick={() => run(item.id, item.text)}>Run</Button>
								{/if}
							</div>
							{#if failed}<p class="text-danger ml-6 text-xs">{item.action_state?.slice(8)}</p>{/if}
						{/if}
						{#if item.done_at}<p class="text-muted ml-6 text-xs" title={datetime(item.done_at)}>{item.done_by_name ?? 'Someone'} · {ago(item.done_at)}</p>{/if}
					</li>
				{/each}
			</ul>
		{:else if list.data}
			<p class="text-muted flex items-center gap-1.5 text-sm"><ListChecks class="size-4" /> No checklist.</p>
		{/if}

		{#if accounts.data?.length}
			<div class="border-border border-t pt-3">
				<h3 class="text-muted mb-1.5 text-xs font-medium">The contact’s directory accounts</h3>
				<ul class="space-y-1">
					{#each accounts.data as a (a.id)}
						<li class="flex items-center gap-2 text-sm">
							<button class="hover:text-accent min-w-0 flex-1 truncate text-left" onclick={() => (drawer = a.id)}>{a.upn || a.username}</button>
							{#if a.locked}<Badge tone="danger">Locked</Badge>{/if}
							{#if !a.enabled}<Badge>Disabled</Badge>{/if}
						</li>
					{/each}
				</ul>
			</div>
		{/if}
	</div>
</section>

{#if drawer}
	<UserDrawer id={drawer} onclose={() => (drawer = null)} onchange={() => (list.reload(), accounts.reload())} />
{/if}
