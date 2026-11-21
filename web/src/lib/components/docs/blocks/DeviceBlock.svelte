<script lang="ts">
	import { ChevronRight, MonitorX } from '@lucide/svelte';
	import { ago } from '#lib/format.js';
	import { parseDevice } from '#lib/docs/markdown.js';
	import type { BlockProps } from '#lib/docs/blocks.js';
	import type { AgentSummary } from '#lib/types.js';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import OsIcon from '#lib/components/OsIcon.svelte';
	import Status from '#lib/components/Status.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import BlockError from './BlockError.svelte';

	/** One of the client's devices: name, online state, OS, and a link to its page. */
	let { seg, ctx }: BlockProps = $props();
	const parsed = $derived(parseDevice(seg.body));

	let state = $state<{ id: string; agent: AgentSummary | null } | { id: string; error: string } | null>(null);
	$effect(() => {
		const id = parsed.agent;
		if (!id || !ctx.clientId) return;
		let live = true;
		ctx.agents().then(
			(m) => live && (state = { id, agent: m.get(id) ?? null }),
			(e) => live && (state = { id, error: e instanceof Error ? e.message : String(e) })
		);
		return () => (live = false);
	});
	const current = $derived(state && state.id === parsed.agent ? state : null);
</script>

{#if parsed.error}
	<BlockError {seg} message={parsed.error} />
{:else if !ctx.clientId}
	<div class="doc-block doc-device doc-device-missing">
		<MonitorX class="text-muted size-5 shrink-0" aria-hidden="true" />
		<p class="text-muted text-sm">A device of the client goes here.</p>
	</div>
{:else if !current}
	<div class="doc-block doc-device" aria-busy="true"><span class="sr-only">Loading device</span>
		<Skeleton class="size-9 rounded-md" />
		<div class="flex-1 space-y-1.5"><Skeleton class="h-4 w-40" /><Skeleton class="h-3 w-56" /></div>
	</div>
{:else if 'error' in current}
	<div class="doc-block doc-device doc-device-missing">
		<MonitorX class="text-muted size-5 shrink-0" aria-hidden="true" />
		<p class="text-muted text-sm">Couldn’t load this device: {current.error}</p>
	</div>
{:else if !current.agent}
	<div class="doc-block doc-device doc-device-missing">
		<MonitorX class="text-muted size-5 shrink-0" aria-hidden="true" />
		<div class="min-w-0">
			<p class="text-sm font-medium">Device not found</p>
			<p class="text-muted text-xs">It was removed, or it isn’t one of this client’s devices.</p>
		</div>
	</div>
{:else}
	{@const a = current.agent}
	<a class="doc-block doc-device group hover:border-border-strong hover:bg-hover/40" href="/agents/{a.id}">
		<span class="bg-sunken flex size-9 shrink-0 items-center justify-center rounded-md"><OsIcon os={a.os_family} /></span>
		<span class="min-w-0 flex-1">
			<span class="flex flex-wrap items-center gap-x-2.5 gap-y-0.5">
				<span class="font-medium group-hover:text-accent truncate">{a.hostname}</span>
				<Status online={a.online} />
				{#if a.health !== 'healthy' && a.health !== 'unknown'}<HealthBadge health={a.health} agent={a} />{/if}
			</span>
			<span class="text-muted block truncate text-xs">{a.os_version || a.os_name} · {a.site_name}{a.online ? '' : ` · last seen ${ago(a.last_seen_at)}`}</span>
		</span>
		<ChevronRight class="text-subtle group-hover:text-accent size-4 shrink-0" aria-hidden="true" />
	</a>
{/if}
