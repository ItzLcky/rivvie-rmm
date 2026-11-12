<script lang="ts">
	import { Pencil, Plus, Trash2, Users } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Team } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';

	let { onchange }: { onchange: () => void } = $props();

	const teams = resource(() => api.get<Team[]>('/teams'));
	const meta = resource(() => ticketMeta());
	const nameOf = (id: string) => meta.data?.technicians.find((t) => t.id === id)?.name ?? 'Former user';

	let draft = $state<{ id: string | null; name: string; member_ids: string[] } | null>(null);
	let saving = $state(false);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		const d = draft!;
		saving = true;
		const ok = await attempt(() => (d.id ? api.put(`/teams/${d.id}`, d) : api.post('/teams', d)), `${d.name} saved.`);
		saving = false;
		if (ok) {
			draft = null;
			teams.reload();
			onchange();
		}
	}
	async function remove(t: Team) {
		const ok = await confirmAction({ title: `Delete ${t.name}?`, message: 'Its tickets keep their assignees but no longer have a team.', confirmLabel: 'Delete team', danger: true });
		if (ok && (await attempt(() => api.del(`/teams/${t.id}`), `${t.name} deleted.`))) {
			teams.reload();
			onchange();
		}
	}
</script>

<section class="card" aria-labelledby="teams-h">
	<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="teams-h" class="font-semibold">Teams</h2>
			<p class="text-muted text-xs">Assign tickets to a team as well as (or instead of) a person. Members get a “My teams” view.</p>
		</div>
		<Button variant="primary" icon={Plus} onclick={() => (draft = { id: null, name: '', member_ids: [] })}>Add team</Button>
	</header>
	<Async res={teams} compact>
		{#snippet children(list)}
			{#if list.length}
				<ul class="divide-border divide-y">
					{#each list as t (t.id)}
						<li class="flex items-center gap-3 px-5 py-3 text-sm">
							<div class="min-w-0 flex-1">
								<div class="font-medium">{t.name} <span class="text-muted text-xs font-normal">· {plural(t.open_tickets, 'open ticket')}</span></div>
								<div class="text-muted truncate text-xs">{t.member_ids.length ? t.member_ids.map(nameOf).join(', ') : 'No members'}</div>
							</div>
							<IconButton icon={Pencil} size="sm" label="Edit {t.name}" onclick={() => (draft = { id: t.id, name: t.name, member_ids: [...t.member_ids] })} />
							<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {t.name}" onclick={() => remove(t)} />
						</li>
					{/each}
				</ul>
			{:else}
				<EmptyState compact icon={Users} title="No teams" description="For example Tier 1, Projects or Field service." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if draft}
	<Modal title={draft.id ? `Edit ${draft.name}` : 'Add team'} onclose={() => (draft = null)}>
		<form id="team-form" class="space-y-4" onsubmit={save}>
			<Field label="Name" id="team-name" required><Input id="team-name" bind:value={draft.name} required maxlength={100} /></Field>
			<fieldset>
				<legend class="label">Members</legend>
				<div class="grid gap-1.5 sm:grid-cols-2">
					{#each meta.data?.technicians ?? [] as u (u.id)}
						<Checkbox
							checked={draft.member_ids.includes(u.id)}
							onchange={(on: boolean) => (draft!.member_ids = on ? [...draft!.member_ids, u.id] : draft!.member_ids.filter((x) => x !== u.id))}
						>{u.name}</Checkbox>
					{/each}
				</div>
			</fieldset>
		</form>
		{#snippet footer()}
			<Button onclick={() => (draft = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="team-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
