<script lang="ts">
	import { ShieldAlert } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { num, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { qs } from '#lib/url.svelte.js';
	import type { VulnSummary } from '#lib/vulns.js';

	/** One line for the dashboard and a client's overview: open critical and high findings. Hidden until devices are assessed. */
	let { clientId = null, class: klass = '' }: { clientId?: string | null; class?: string } = $props();
	const res = resource(() => (allowed('security.read') ? api.get<VulnSummary>(`/vulnerabilities/summary${qs({ client_id: clientId })}`) : Promise.resolve(null)));
	const href = $derived(`/vulnerabilities${qs({ client: clientId })}`);
</script>

{#if res.data && res.data.assessed > 0}
	{@const s = res.data}
	{@const hot = s.critical + s.high > 0}
	<a {href} class="card hover:border-border-strong flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm transition-[border-color] {klass}">
		<ShieldAlert class={hot ? 'text-danger size-4' : 'text-muted size-4'} aria-hidden="true" />
		<span class="font-medium">Vulnerabilities</span>
		{#if hot}
			<span><span class="text-danger font-semibold tabular">{num(s.critical)}</span> critical</span>
			<span><span class="text-warning font-semibold tabular">{num(s.high)}</span> high</span>
			<span class="text-muted">on {plural(s.devices_affected, 'device')}{s.kev ? ` · ${plural(s.kev, 'known exploited CVE')}` : ''}</span>
		{:else}
			<span class="text-muted">No critical or high findings on {plural(s.assessed, 'assessed device')}</span>
		{/if}
	</a>
{/if}
