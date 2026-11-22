<script lang="ts">
	import { page } from '$app/state';
	import { X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { datetime, ms } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { opLabels, providerLabels, runLabel, runTone, type SoftwareRun } from '#lib/software.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	const id = $derived(page.params.id!);
	const run = resource(() => api.get<SoftwareRun>(`/software/runs/${id}`), { keep: false });
	liveReload(() => run.reload(), (e) => e.type === 'software' && e.agent_id === run.data?.agent_id, { debounceMs: 300, pollMs: 5000 });

	async function cancel() {
		if (await attempt(() => api.post(`/software/runs/${id}/cancel`), 'Cancelled.')) run.reload();
	}
</script>

<svelte:head><title>{run.data ? `${opLabels[run.data.op]} ${run.data.package_name}` : 'Software run'}</title></svelte:head>

<Async res={run}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-64" /></div>
		<div class="card space-y-2 p-4"><Skeleton lines={6} /></div>
	{/snippet}
	{#snippet children(r)}
		<PageHeader title="{opLabels[r.op]} {r.package_name}" crumbs={[{ label: 'Software', href: '/software' }, { label: 'History', href: '/software?tab=runs' }, { label: datetime(r.created_at) }]}>
			{#snippet subtitle()}
				<Badge tone={runTone[r.status]}>{runLabel[r.status]}</Badge>
				<span>{r.trigger === 'policy' ? 'Started by a policy' : `Started by ${r.created_by_name ?? 'a user'}`}</span>
				<a class="link" href="/agents/{r.agent_id}?tab=deployments">{r.hostname}</a>
				{#if r.package_id}<a class="link" href="/software/{r.package_id}">Package</a>{/if}
			{/snippet}
			{#snippet actions()}
				{#if r.status === 'queued' && can('technician')}<Button icon={X} onclick={cancel}>Cancel</Button>{/if}
			{/snippet}
		</PageHeader>

		<div class="grid gap-4 lg:grid-cols-[minmax(16rem,20rem)_1fr]">
			<section class="card self-start p-4" aria-label="Summary">
				<dl class="dl">
					<dt>Provider</dt><dd>{r.provider ? (providerLabels[r.provider] ?? r.provider) : '–'}</dd>
					<dt>Version</dt><dd class="font-mono text-xs">{r.from_version ?? '–'} → {r.to_version ?? '–'}</dd>
					<dt>Created</dt><dd>{datetime(r.created_at)}</dd>
					<dt>Sent</dt><dd>{r.sent_at ? datetime(r.sent_at) : '–'}</dd>
					<dt>Finished</dt><dd>{r.finished_at ? datetime(r.finished_at) : '–'}</dd>
					<dt>Duration</dt><dd>{r.duration_ms != null ? ms(r.duration_ms) : '–'}</dd>
				</dl>
				{#if r.reboot_required}<p class="mt-3"><Badge tone="warning">Restart pending</Badge></p>{/if}
				{#if r.status === 'sent' && (r.stage || r.progress)}<p class="text-muted mt-3 text-xs" role="status">{r.stage ?? ''}{r.progress ? `: ${r.progress}` : ''}</p>{/if}
				{#if r.error}<p class="text-danger mt-3 text-sm" role="alert">{r.error}</p>{/if}
			</section>
			<section class="card min-w-0" aria-label="Output">
				<header class="border-border flex items-center justify-between border-b px-4 py-2">
					<h2 class="panel-title">Package manager output</h2>
					{#if r.output}<CopyButton text={r.output} label="Copy output" />{/if}
				</header>
				{#if r.output}
					<pre class="max-h-[60vh] overflow-auto p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap" style="background: var(--terminal-bg); color: var(--terminal-fg)">{r.output}</pre>
				{:else}
					<p class="text-muted px-4 py-6 text-center text-sm">{r.status === 'sent' || r.status === 'queued' ? 'Output arrives when the run finishes.' : 'No output.'}</p>
				{/if}
			</section>
		</div>
	{/snippet}
</Async>
