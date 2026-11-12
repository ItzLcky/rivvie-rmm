<script lang="ts">
	import { page } from '$app/state';
	import { CircleCheck, CircleX, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { datetime, ms, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { rebootLabel } from '#lib/patches.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { PatchRunDetail } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import PatchBadge from '#lib/components/PatchBadge.svelte';

	const id = $derived(page.params.id!);
	const run = resource(() => api.get<PatchRunDetail>(`/patch-runs/${id}`), { keep: false });
	liveReload(() => run.reload(), (e) => e.type === 'patches' && e.agent_id === run.data?.agent_id, { debounceMs: 300, pollMs: 5000 });

	async function cancel() {
		if (await attempt(() => api.post(`/patch-runs/${id}/cancel`), 'Install cancelled.')) run.reload();
	}
</script>

<svelte:head><title>Install on {run.data?.hostname ?? '…'}</title></svelte:head>

<Async res={run}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-64" /></div>
		<div class="card space-y-2 p-4"><Skeleton lines={6} /></div>
	{/snippet}
	{#snippet children(r)}
		<PageHeader
			title="Install on {r.hostname}"
			crumbs={[{ label: 'Patches', href: '/patches' }, { label: 'Install history', href: '/patches?tab=history' }, { label: datetime(r.created_at) }]}
		>
			{#snippet subtitle()}
				<PatchBadge kind="run" value={r.status} />
				{#if r.status === 'sent' && r.percent != null}<span class="tabular">{r.percent}%</span>{/if}
				<span>{r.trigger === 'policy' ? 'Started by the patch policy' : `Started by ${r.created_by_name ?? 'a user'}`}</span>
				<a class="link" href="/agents/{r.agent_id}?tab=patches">{r.hostname}</a>
			{/snippet}
			{#snippet actions()}
				{#if r.status === 'queued' && can('technician')}<Button icon={X} onclick={cancel}>Cancel</Button>{/if}
			{/snippet}
		</PageHeader>

		<div class="grid gap-4 lg:grid-cols-[minmax(16rem,20rem)_1fr]">
			<section class="card self-start p-4" aria-label="Summary">
				<dl class="dl">
					<dt>Updates</dt><dd>{r.succeeded} of {plural(r.updates, 'update')} installed</dd>
					<dt>Restart</dt><dd>{rebootLabel(r.reboot_policy)}{#if r.rebooting}<span class="block"><Badge tone="warning">Restarting</Badge></span>{:else if r.reboot_required}<span class="block"><Badge tone="warning">Restart pending</Badge></span>{/if}</dd>
					<dt>Created</dt><dd>{datetime(r.created_at)}</dd>
					<dt>Sent</dt><dd>{r.sent_at ? datetime(r.sent_at) : '–'}</dd>
					<dt>Finished</dt><dd>{r.finished_at ? datetime(r.finished_at) : '–'}</dd>
					<dt>Duration</dt><dd>{r.duration_ms != null ? ms(r.duration_ms) : '–'}</dd>
				</dl>
				{#if r.status === 'sent' && (r.stage || r.progress)}
					<p class="text-muted mt-3 text-xs" role="status">{r.stage ?? ''}{r.progress ? `: ${r.progress}` : ''}</p>
				{/if}
				{#if r.error}<p class="text-danger mt-3 text-sm" role="alert">{r.error}</p>{/if}
			</section>

			<div class="min-w-0 space-y-4">
				<section class="card overflow-x-auto" aria-label="Updates in this install">
					<table class="table">
						<thead><tr><th>Update</th><th>Severity</th><th>Result</th></tr></thead>
						<tbody>
							{#each r.items as it (it.update_id)}
								<tr>
									<td>
										<div class="font-medium break-words">{it.title ?? it.update_id}</div>
										{#if it.kb}<div class="text-muted font-mono text-xs">{it.kb}</div>{/if}
										{#if it.message}<div class={it.ok ? 'text-muted text-xs' : 'text-danger text-xs'}>{it.message}</div>{/if}
									</td>
									<td><PatchBadge kind="severity" value={it.severity} /></td>
									<td>
										{#if it.ok === true}<Badge tone="success" icon={CircleCheck}>Installed</Badge>
										{:else if it.ok === false}<Badge tone="danger" icon={CircleX}>Failed</Badge>
										{:else}<span class="text-muted">–</span>{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</section>
				<section class="card" aria-label="Output">
					<header class="border-border flex items-center justify-between border-b px-4 py-2">
						<h2 class="panel-title">Package manager output</h2>
						{#if r.output}<CopyButton text={r.output} label="Copy output" />{/if}
					</header>
					{#if r.output}
						<pre class="max-h-[60vh] overflow-auto p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap" style="background: var(--terminal-bg); color: var(--terminal-fg)">{r.output}</pre>
					{:else}
						<p class="text-muted px-4 py-6 text-center text-sm">{r.status === 'sent' || r.status === 'queued' ? 'Output arrives when the install finishes.' : 'No output.'}</p>
					{/if}
				</section>
			</div>
		</div>
	{/snippet}
</Async>
