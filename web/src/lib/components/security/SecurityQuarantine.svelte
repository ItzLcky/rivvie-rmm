<script lang="ts">
	import { Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId } from '#lib/scope.svelte.js';
	import type { QuarantineRow } from '#lib/types.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import QuarantineList from './QuarantineList.svelte';

	/** Every quarantined file across the fleet (or the selected client). */
	const show = $derived(param('show') === 'all' ? 'all' : 'quarantined');
	let q = $state(param('q'));
	let applied = $state(param('q'));
	$effect(() => {
		const v = q.trim();
		const t = setTimeout(() => (applied = v), 250);
		return () => clearTimeout(t);
	});
	const res = resource(() => api.get<QuarantineRow[]>(`/security/quarantine${qs({ client_id: clientId(), state: show === 'all' ? 'all' : null, q: applied })}`));
	liveReload(() => res.reload(), (e) => e.type === 'security', { debounceMs: 1500, pollMs: 60000 });
</script>

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	<QuarantineList
		id="security-quarantine"
		rows={res.data ?? []}
		showAgent
		loading={res.loading}
		busy={res.busy}
		emptyTitle={applied ? 'No quarantined files match' : show === 'all' ? 'Nothing was ever quarantined' : 'Nothing in quarantine'}
		onchanged={() => res.reload()}
	>
		{#snippet toolbar()}
			<Input icon={Search} placeholder="Path, agent or SHA-256…" aria-label="Search quarantine" class="min-w-0 flex-1 sm:w-72 sm:flex-none" bind:value={q} />
			<Segmented label="Show" value={show} onchange={(v) => setParams({ show: v === 'quarantined' ? null : v })} options={[{ value: 'quarantined', label: 'In quarantine' }, { value: 'all', label: 'All' }]} />
		{/snippet}
	</QuarantineList>
{/if}
