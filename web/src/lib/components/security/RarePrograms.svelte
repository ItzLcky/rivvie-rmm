<script lang="ts">
	import { Crosshair } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import type { RareProgram } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Select from '#lib/ui/Select.svelte';

	/**
	 * Programs that ran on few machines recently and that no database or list knows: leads to
	 * look at, not detections. Counted within the user's clients (and the client picked above).
	 */
	let { onhunt }: { onhunt: (sha256: string) => void } = $props();

	let maxAgents = $state('1');
	let days = $state('7');
	const res = resource(() => api.get<{ items: RareProgram[] }>(`/security/reputation/rare${qs({ max_agents: maxAgents, days, client_id: clientId() })}`));
	const scoped = $derived(currentClient());
</script>

{#snippet hashCell(r: RareProgram)}
	<div class="flex items-start gap-1">
		<span class="min-w-0 font-mono text-xs break-all" title={r.sha256}>{r.sha256.slice(0, 16)}…</span>
		<CopyButton text={r.sha256} label="Copy hash" />
	</div>
	{#if r.agents[0]?.path}<div class="text-muted max-w-md truncate font-mono text-xs" title={r.agents.map((a) => a.path).filter(Boolean).join('\n')}>{r.agents[0].path}</div>{/if}
{/snippet}
{#snippet machinesCell(r: RareProgram)}
	<span class="tabular">{r.seen_on}</span>
	<div class="text-muted max-w-56 truncate text-xs" title={r.agents.map((a) => `${a.hostname} (${a.client_name})`).join('\n')}>
		{#each r.agents.slice(0, 2) as a, i (a.agent_id)}{i ? ', ' : ''}<a class="hover:text-accent" href="/agents/{a.agent_id}?tab=security">{a.hostname}</a>{/each}{r.agents.length > 2 ? ` +${r.agents.length - 2}` : ''}
	</div>
{/snippet}
{#snippet firstCell(r: RareProgram)}<span class="whitespace-nowrap" title={datetime(r.first_seen)}>{ago(r.first_seen)}</span>{/snippet}
{#snippet huntCell(r: RareProgram)}<Button size="sm" icon={Crosshair} onclick={() => onhunt(r.sha256)} aria-label="Hunt for {r.sha256.slice(0, 16)}">Hunt</Button>{/snippet}

<section aria-labelledby="rare-h">
	<DataTable
		id="security-rare"
		caption="Rare programs"
		rows={res.data?.items ?? []}
		key={(r) => r.sha256}
		loading={res.loading && !res.data}
		busy={res.busy}
		scroll={false}
		columns={[
			{ id: 'hash', label: 'Program', cell: hashCell, hideable: false },
			{ id: 'machines', label: 'Machines', cell: machinesCell },
			{ id: 'first', label: 'First seen', cell: firstCell, from: 'sm' },
			{ id: 'hunt', label: '', cell: huntCell, hideable: false, align: 'right', class: 'w-20' }
		] satisfies Column<RareProgram>[]}
	>
		{#snippet toolbar()}
			<div class="min-w-0 flex-1 basis-80">
				<h2 id="rare-h" class="panel-title">Rare programs <span class="text-muted text-xs font-normal">· leads, not detections</span></h2>
				<p class="text-muted text-xs">
					Programs that ran on few machines{scoped ? ` at ${scoped.name}` : ''} recently and that no signature database or hash list knows. Most are in-house tools, installers and fresh updates; one in a temp or download folder is worth a look.
				</p>
			</div>
			<Select aria-label="Seen on at most" class="w-full sm:w-auto" bind:value={maxAgents} options={[{ value: '1', label: 'On 1 machine' }, { value: '2', label: 'On 2 or fewer' }, { value: '5', label: 'On 5 or fewer' }]} />
			<Select aria-label="First seen" class="w-full sm:w-auto" bind:value={days} options={[{ value: '1', label: 'First seen today' }, { value: '7', label: 'In the last 7 days' }, { value: '30', label: 'In the last 30 days' }]} />
		{/snippet}
		{#snippet empty()}
			<EmptyState compact title="No rare programs" description="Every program that ran in that time is known, or ran on more machines. Agents report programs as they start; older agents don’t." />
		{/snippet}
	</DataTable>
	{#if res.data?.items.length === 500}<p class="text-muted mt-1 text-xs">Showing the newest {plural(500, 'program')}.</p>{/if}
</section>
