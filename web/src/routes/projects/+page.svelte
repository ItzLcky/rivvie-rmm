<script lang="ts">
	import { FolderKanban, Plus } from '@lucide/svelte';
	import { goto } from '$app/navigation';
	import { api, qs } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, loadClients, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { projectStatus } from '#lib/work/meta.js';
	import { dateText, localDay } from '#lib/work/time.js';
	import type { Project } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import BudgetBar from '#lib/components/work/BudgetBar.svelte';
	import ProjectModal from '#lib/components/work/ProjectModal.svelte';

	const which = $derived(param('state') === 'all' ? 'all' : 'open');
	const list = resource(() => api.get<Project[]>(`/projects${qs({ state: which, client_id: clientId() })}`));
	const scoped = $derived(currentClient());
	const today = localDay();
	let creating = $state(false);
	$effect(() => {
		loadClients();
	});
	const late = (p: Project) => !!p.due_date && p.due_date < today && (p.status === 'active' || p.status === 'planned' || p.status === 'on_hold');
</script>

<PageHeader
	title="Projects"
	count={list.data?.length ?? null}
	description={scoped ? `${scoped.name}'s projects.` : 'Planned work with a budget: tasks by phase, the time logged against it and how much is left.'}
>
	{#snippet actions()}{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (creating = true)}>New project</Button>{/if}{/snippet}
</PageHeader>

<div class="mb-3">
	<Segmented
		label="Which projects"
		value={which}
		onchange={(v) => setParams({ state: v === 'open' ? null : v })}
		options={[
			{ value: 'open', label: 'Open' },
			{ value: 'all', label: 'All' }
		]}
	/>
</div>

<Async res={list}>
	{#snippet children(rows)}
		{#if !rows.length}
			<div class="card">
				<EmptyState icon={FolderKanban} title={which === 'open' ? 'No open projects' : 'No projects'} description="A project groups tasks and tickets for one client under a budget of hours.">
					{#snippet action()}{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (creating = true)}>New project</Button>{/if}{/snippet}
				</EmptyState>
			</div>
		{:else}
			<div class="card overflow-x-auto">
				<table class="table">
					<caption class="sr-only">Projects</caption>
					<thead>
						<tr>
							<th>Project</th>
							{#if !scoped}<th class="hidden md:table-cell">Client</th>{/if}
							<th>Status</th>
							<th class="hidden sm:table-cell">Due</th>
							<th class="hidden lg:table-cell">Tasks</th>
							<th class="w-56">Budget</th>
						</tr>
					</thead>
					<tbody>
						{#each rows as p (p.id)}
							{@const s = projectStatus(p.status)}
							<tr>
								<td class="min-w-40">
									<a class="font-medium hover:underline" href={withClient(`/projects/${p.id}`)}>{p.name}</a>
									<span class="text-muted block text-xs">
										{#if !scoped}<span class="md:hidden">{p.client_name} · </span>{/if}{p.owner_name ?? 'No owner'}
									</span>
								</td>
								{#if !scoped}<td class="hidden md:table-cell"><a class="hover:underline" href="/clients/{p.client_id}">{p.client_name}</a></td>{/if}
								<td><Badge tone={s.tone}>{s.label}</Badge></td>
								<td class="hidden whitespace-nowrap sm:table-cell {late(p) ? 'text-danger font-medium' : ''}">
									{dateText(p.due_date)}{#if late(p)}<span class="sr-only"> (overdue)</span>{/if}
								</td>
								<td class="hidden tabular lg:table-cell">{p.tasks ? `${p.tasks_done} / ${p.tasks}` : '–'}</td>
								<td><BudgetBar logged={p.logged_minutes} budget={p.budget_minutes} /></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{/snippet}
</Async>

{#if creating}
	<ProjectModal clientId={clientId() || undefined} onclose={() => (creating = false)} onsaved={(id) => goto(withClient(`/projects/${id}`))} />
{/if}
