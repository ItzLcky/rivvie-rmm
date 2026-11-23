<script lang="ts">
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { runReason, triggerLabels } from '#lib/policy/policy.js';
	import type { AutomationRun } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import RunStatus from './RunStatus.svelte';

	/** What automation policies did on one device, newest first. */
	let { agentId }: { agentId: string } = $props();
	const res = resource(() => api.get<AutomationRun[]>(`/agents/${agentId}/automations`));
	const shown = (v: unknown) => (v == null ? 'no value' : String(v));
	/** What fired the run, for the triggers that name something. */
	function cause(r: AutomationRun): string {
		const c = r.context;
		if (r.trigger === 'tag_added' && c.tag) return `tag ${c.tag}`;
		if (r.trigger === 'field_changed' && c.field) return `${c.field}: ${shown(c.from)} → ${shown(c.to)}`;
		return '';
	}
</script>

<section class="card min-w-0 xl:col-span-2" aria-labelledby="ap-automations">
	<header class="panel-head">
		<div class="min-w-0">
			<h2 id="ap-automations" class="panel-title">Automation history</h2>
			<p class="text-muted text-xs">Scripts that automation policies started on this device, and the ones they held back or skipped.</p>
		</div>
	</header>
	<Async {res}>
		{#snippet children(runs)}
			{#if runs.length}
				<ul class="divide-border divide-y text-sm">
					{#each runs as r (r.id)}
						<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5">
							<div class="min-w-0 flex-1">
								<div class="flex flex-wrap items-center gap-2">
									<a class="hover:text-accent font-medium" href="/policies/items/{r.item_id}">{r.item_name}</a>
									<RunStatus status={r.status} reason={r.reason} />
								</div>
								<p class="text-muted text-xs">
									{triggerLabels[r.trigger]}{cause(r) ? ` (${cause(r)})` : ''}{r.script_name ? ` · ${r.script_name}` : ''}{r.reason ? ` · ${runReason(r.reason)}` : ''}{r.attempts > 1 ? ` · attempt ${r.attempts}` : ''}
								</p>
							</div>
							<span class="text-muted text-xs whitespace-nowrap" title={datetime(r.created_at)}>{ago(r.created_at)}</span>
							{#if r.job_id}<a class="link text-xs" href="/jobs/{r.job_id}">Output{r.exit_code != null ? ` (exit ${r.exit_code})` : ''}</a>{/if}
						</li>
					{/each}
				</ul>
			{:else}
				<EmptyState compact title="No automations have run here" description="Event triggers, enrollment and run-once scripts from the device’s policy sets show up here." />
			{/if}
		{/snippet}
	</Async>
</section>
