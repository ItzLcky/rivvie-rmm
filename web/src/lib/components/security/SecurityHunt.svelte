<script lang="ts">
	import { untrack } from 'svelte';
	import { Crosshair, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, plural } from '#lib/format.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { eventKindLabels, eventKinds } from '#lib/security.js';
	import type { EventKind, HuntResult, PrevalenceRow } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import EventTable from './EventTable.svelte';

	/**
	 * Asks every online agent with our sensor to search its telemetry at once: for a command
	 * line, a domain, an address, or a file hash.
	 */
	let query = $state(param('sha256') || param('text'));
	let kinds = $state<EventKind[]>([...eventKinds]);
	let minutes = $state('1440');
	let busy = $state(false);
	let error = $state('');
	let result = $state<HuntResult | null>(null);
	let prevalence = $state<PrevalenceRow[] | null>(null);
	let searchedFor = $state('');

	const scoped = $derived(currentClient());
	const isHash = (v: string) => /^[0-9a-f]{64}$/i.test(v.trim());
	const ranges = [
		{ value: '60', label: 'Last hour' },
		{ value: '1440', label: 'Last 24 hours' },
		{ value: '10080', label: 'Last 7 days' },
		{ value: '43200', label: 'Last 30 days' }
	];

	async function hunt(e?: SubmitEvent) {
		e?.preventDefault();
		const v = query.trim();
		if (!v) {
			error = 'Search for some text, or a file’s SHA-256';
			return;
		}
		if (!kinds.length) {
			error = 'Pick at least one kind of event';
			return;
		}
		error = '';
		busy = true;
		const hash = isHash(v);
		setParams(hash ? { sha256: v.toLowerCase(), text: null } : { text: v, sha256: null });
		try {
			const [r, p] = await Promise.all([
				api.post<HuntResult>('/security/hunt', {
					text: hash ? undefined : v,
					sha256: hash ? v.toLowerCase() : undefined,
					kinds: kinds.length === eventKinds.length ? undefined : kinds.join(','),
					minutes: Number(minutes),
					limit: 50,
					client_id: clientId() || undefined
				}),
				hash ? api.get<{ sha256: string; agents: PrevalenceRow[] }>(`/security/prevalence?sha256=${v.toLowerCase()}`).then((x) => x.agents) : Promise.resolve(null)
			]);
			result = r;
			prevalence = p;
			searchedFor = v;
		} catch (err) {
			result = null;
			prevalence = null;
			error = err instanceof Error ? err.message : String(err);
		} finally {
			busy = false;
		}
	}

	// Arriving with ?sha256= (from a detection) runs the hunt straight away.
	$effect(() => {
		if (untrack(() => query.trim())) untrack(() => hunt());
	});
</script>

<section class="card mb-4" aria-labelledby="hunt-h">
	<header class="border-border border-b px-4 py-2.5">
		<h2 id="hunt-h" class="text-sm font-semibold">Hunt across {scoped ? `${scoped.name}'s agents` : 'the fleet'}</h2>
		<p class="text-muted text-xs">Every online agent running our sensor searches its own telemetry and answers within a few seconds. Offline agents can’t be searched.</p>
	</header>
	<form class="flex flex-wrap items-end gap-x-4 gap-y-3 px-4 py-3" onsubmit={hunt}>
		<div class="min-w-0 flex-1 basis-72">
			<label for="hunt-q" class="label">Text or SHA-256</label>
			<Input id="hunt-q" icon={Search} class="font-mono" spellcheck={false} placeholder="mimikatz, evil.example.com, 185.220.101.4, or a file hash" bind:value={query} invalid={!!error} aria-describedby={error ? 'hunt-err' : undefined} />
		</div>
		<div>
			<label for="hunt-range" class="label">When</label>
			<Select id="hunt-range" class="w-full sm:w-44" bind:value={minutes} options={ranges} />
		</div>
		<fieldset class="min-w-0">
			<legend class="label">Kinds</legend>
			<div class="flex min-h-8 flex-wrap items-center gap-x-3 gap-y-1">
				{#each eventKinds as k (k)}
					<Checkbox checked={kinds.includes(k)} onchange={(on) => (kinds = on ? [...new Set([...kinds, k])] : kinds.filter((x) => x !== k))}>{eventKindLabels[k]}</Checkbox>
				{/each}
			</div>
		</fieldset>
		<Button type="submit" variant="primary" icon={Crosshair} loading={busy}>Hunt</Button>
		{#if error}<p id="hunt-err" class="text-danger w-full text-sm" role="alert">{error}</p>{/if}
	</form>
</section>

{#if prevalence}
	<section class="card mb-4" aria-labelledby="prev-h">
		<header class="border-border border-b px-4 py-2.5">
			<h2 id="prev-h" class="text-sm font-semibold">Known from detections and quarantine</h2>
			<p class="text-muted text-xs">Where the server has already seen this hash, including offline machines.</p>
		</header>
		{#if prevalence.length}
			<ul class="divide-border divide-y">
				{#each prevalence as p (p.agent_id + p.how)}
					<li class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-4 py-2 text-sm">
						<a class="hover:text-accent font-medium" href="/agents/{p.agent_id}?tab=security">{p.hostname}</a>
						<span class="text-muted text-xs">{p.client_name}</span>
						<span class="text-muted min-w-0 flex-1 text-xs">{p.how}</span>
						<span class="text-muted text-xs" title={datetime(p.first_seen)}>first {ago(p.first_seen)}</span>
					</li>
				{/each}
			</ul>
		{:else}
			<p class="text-muted px-4 py-3 text-sm">No detection or quarantined file has this hash.</p>
		{/if}
	</section>
{/if}

{#if result}
	<div class="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm" role="status">
		<span class="font-medium">{result.hits.length ? `Found on ${plural(result.hits.length, 'agent')}` : 'No matches'}</span>
		<span class="text-muted">Searched {plural(result.searched, 'agent')}{result.offline ? ` · ${result.offline} offline, not searched` : ''}{result.errors.length ? ` · ${plural(result.errors.length, 'error')}` : ''}</span>
	</div>
	{#if result.errors.length}
		<ul class="border-warning/40 bg-warning-soft mb-4 space-y-0.5 rounded-md border px-3 py-2 text-sm" aria-label="Agents that couldn't search">
			{#each result.errors as e (e.agent_id)}
				<li><a class="font-medium hover:underline" href="/agents/{e.agent_id}?tab=security">{e.hostname}</a>: <span class="text-muted">{e.error}</span></li>
			{/each}
		</ul>
	{/if}
	{#each result.hits as h (h.agent_id)}
		<section class="card mb-4" aria-label="Matches on {h.hostname}">
			<header class="border-border flex flex-wrap items-baseline gap-x-3 border-b px-4 py-2.5">
				<h3 class="text-sm font-semibold"><a class="hover:text-accent" href="/agents/{h.agent_id}?tab=security">{h.hostname}</a></h3>
				<span class="text-muted text-xs">{h.client_name}</span>
				<span class="text-muted ml-auto text-xs">{plural(h.events.length, 'event')}{h.truncated ? ' (more not shown)' : ''}</span>
			</header>
			<EventTable events={h.events} caption="Matches on {h.hostname}" showDate={Number(minutes) >= 1440} />
		</section>
	{:else}
		<div class="card">
			<EmptyState compact icon={Crosshair} title="Nothing matched “{searchedFor}”" description="No online agent recorded it in that time. Telemetry is kept as long as each agent’s store has room (the security policy sets its size)." />
		</div>
	{/each}
{/if}
