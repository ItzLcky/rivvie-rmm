<script lang="ts">
	import { Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { plural } from '#lib/format.js';
	import { eventKindLabels, eventKinds } from '#lib/security.js';
	import type { EventKind, TelemetryEvent, TelemetryResult } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import EventTable from './EventTable.svelte';

	/**
	 * Searches one agent's local telemetry store (it never leaves the machine until asked for).
	 * The agent answers live, so it has to be online.
	 */
	let {
		agentId,
		online,
		title = 'Telemetry',
		highlight
	}: { agentId: string; online: boolean; title?: string; highlight?: (e: TelemetryEvent) => boolean } = $props();

	let text = $state('');
	let kinds = $state<EventKind[]>([...eventKinds]);
	let minutes = $state('60');
	let busy = $state(false);
	let error = $state('');
	let result = $state<TelemetryResult | null>(null);

	const ranges = [
		{ value: '15', label: 'Last 15 minutes' },
		{ value: '60', label: 'Last hour' },
		{ value: '240', label: 'Last 4 hours' },
		{ value: '1440', label: 'Last 24 hours' },
		{ value: '10080', label: 'Last 7 days' }
	];

	async function search(e: SubmitEvent) {
		e.preventDefault();
		if (!kinds.length) {
			error = 'Pick at least one kind of event';
			return;
		}
		busy = true;
		error = '';
		try {
			result = await api.get<TelemetryResult>(
				`/agents/${agentId}/telemetry${qs({ text: text.trim(), kinds: kinds.length === eventKinds.length ? null : kinds.join(','), minutes, limit: 500 })}`
			);
		} catch (err) {
			result = null;
			error = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}
</script>

<section class="card" aria-labelledby="telemetry-h">
	<header class="border-border border-b px-4 py-2.5">
		<h2 id="telemetry-h" class="text-sm font-semibold">{title}</h2>
		<p class="text-muted text-xs">What our sensor recorded on this machine: processes, connections, file, registry and module events. Kept on the machine; searched live.</p>
	</header>
	<form class="border-border flex flex-wrap items-end gap-x-4 gap-y-3 border-b px-4 py-3" onsubmit={search}>
		<div class="min-w-0 flex-1 basis-56">
			<label for="tel-text" class="label">Contains</label>
			<Input id="tel-text" icon={Search} placeholder="powershell, 10.0.0.5, invoice…" spellcheck={false} bind:value={text} disabled={!online} />
		</div>
		<div>
			<label for="tel-range" class="label">When</label>
			<Select id="tel-range" class="w-full sm:w-44" bind:value={minutes} options={ranges} disabled={!online} />
		</div>
		<fieldset class="min-w-0">
			<legend class="label">Kinds</legend>
			<div class="flex h-8 flex-wrap items-center gap-x-3 gap-y-1">
				{#each eventKinds as k (k)}
					<Checkbox disabled={!online} checked={kinds.includes(k)} onchange={(on) => (kinds = on ? [...new Set([...kinds, k])] : kinds.filter((x) => x !== k))}>{eventKindLabels[k]}</Checkbox>
				{/each}
			</div>
		</fieldset>
		<Button type="submit" variant="primary" icon={Search} loading={busy} disabled={!online} title={online ? undefined : 'The agent is offline'}>Search</Button>
	</form>
	{#if !online}
		<EmptyState compact title="The agent is offline" description="Telemetry stays on the machine, so it can only be searched while the agent is connected." />
	{:else if error}
		<p class="text-danger px-4 py-3 text-sm" role="alert">{error}</p>
	{:else if result}
		{#if result.error}<p class="text-warning border-border border-b px-4 py-2 text-xs" role="status">The agent answered with a problem: {result.error}</p>{/if}
		{#if result.events.length}
			<p class="text-muted px-4 pt-2 text-xs" role="status">{plural(result.events.length, 'event')}{result.truncated ? ', newest first; narrow the search to see the rest' : ''}</p>
			<EventTable events={result.events} caption="Telemetry events" {highlight} showDate={Number(minutes) >= 1440} />
		{:else}
			<EmptyState compact title="No events match" description="Try a longer time range or fewer words." />
		{/if}
	{:else}
		<p class="text-muted px-4 py-3 text-sm">Search to see events. Leave “Contains” empty to list the most recent ones.</p>
	{/if}
</section>
