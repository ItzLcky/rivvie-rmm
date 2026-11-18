<script lang="ts">
	import { ScrollText, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { levelTone } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { LogEvent } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import { ROOT_SET } from '#lib/policy/policy.js';

	/** Log entries that matched this agent's log policies (watchers run on the agent). */
	let { agentId }: { agentId: string } = $props();
	let q = $state('');
	let search = $state('');
	let level = $state('');
	$effect(() => {
		const v = q;
		const t = setTimeout(() => (search = v.trim()), 300);
		return () => clearTimeout(t);
	});
	const res = resource(() => api.get<LogEvent[]>(`/agents/${agentId}/log-events${qs({ q: search, level })}`));
	liveReload(() => res.reload(), (e) => e.type === 'alert' && e.agent_id === agentId, { debounceMs: 1000, pollMs: 60000 });
	let older = $state<LogEvent[]>([]);
	let more = $state(true);
	$effect(() => {
		void res.data;
		older = [];
		more = (res.data?.length ?? 0) === 200;
	});
	async function loadOlder() {
		const all = [...(res.data ?? []), ...older];
		const before = all.at(-1)?.id;
		try {
			const page = await api.get<LogEvent[]>(`/agents/${agentId}/log-events${qs({ q: search, level, before })}`);
			older = [...older, ...page];
			more = page.length === 200;
		} catch (e) {
			toast.error(e);
		}
	}
</script>

<section class="card" aria-label="Event log">
	<div class="border-border flex flex-wrap items-center gap-2 border-b p-3">
		<Input icon={Search} data-search placeholder="Message or source…" aria-label="Search log entries" class="w-full sm:w-72" bind:value={q} />
		<Select aria-label="Level" class="w-auto" bind:value={level} options={[{ value: '', label: 'Any level' }, { value: 'critical', label: 'Critical' }, { value: 'error', label: 'Error' }, { value: 'warning', label: 'Warning' }, { value: 'info', label: 'Information' }]} />
		<span class="text-muted ml-auto text-xs">Entries matched by log policies, kept 30 days.</span>
	</div>
	<Async {res} compact>
		{#snippet children(rows)}
			{@const list = [...rows, ...older]}
			{#if list.length}
				<ol class="divide-border divide-y">
					{#each list as e (e.id)}
						<li class="px-4 py-2.5 text-sm">
							<div class="text-muted mb-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
								<Badge tone={levelTone[e.level]}>{e.level}</Badge>
								<span class="text-fg font-medium">{e.source || '–'}</span>
								{#if e.event_id != null}<span>ID {e.event_id}</span>{/if}
								{#if e.policy_name}<span>· {e.policy_name}</span>{/if}
								<time class="ml-auto" datetime={e.ts} title={datetime(e.ts)}>{ago(e.ts)}</time>
							</div>
							<pre class="font-mono text-xs break-words whitespace-pre-wrap">{e.message}</pre>
						</li>
					{/each}
				</ol>
				{#if more}<div class="border-border border-t p-2 text-center"><Button size="sm" onclick={loadOlder}>Load older</Button></div>{/if}
			{:else}
				<EmptyState
					compact
					icon={ScrollText}
					title={search || level ? 'No entries match' : 'No matched entries'}
					description={search || level ? undefined : 'Add an “Event log match” alert policy to watch the journal (Linux) or the Event Log (Windows) for entries you care about.'}
				>
					{#snippet action()}{#if !search && !level}<Button size="sm" href="/policies/sets/{ROOT_SET}?section=alerts&item=new&kind=log">New log policy</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</Async>
</section>
