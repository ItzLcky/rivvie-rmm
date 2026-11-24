<script lang="ts">
	import { page } from '$app/state';
	import { Check, CheckCheck, Copy, Pencil } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { kindLabels, levelTone } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { AlertDetail } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import AlertStateBadge from '#lib/components/AlertStateBadge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import PageTimeline from '#lib/oncall/PageTimeline.svelte';

	const id = $derived(page.params.id!);
	const res = resource(() => api.get<AlertDetail>(`/alerts/${id}`), { keep: false });
	liveReload(() => res.reload(), (e) => e.type === 'alert' && e.id === id, { debounceMs: 500 });

	async function act(action: 'acknowledge' | 'resolve') {
		if (await attempt(() => api.post(`/alerts/${id}/${action}`), action === 'acknowledge' ? 'Acknowledged.' : 'Resolved.')) res.reload();
	}

	/** Details as label/value pairs; ids that have their own page become links. */
	function facts(d: Record<string, unknown>): { label: string; value: string; href?: string }[] {
		return Object.entries(d)
			.filter(([, v]) => v !== null && v !== '' && typeof v !== 'object')
			.map(([k, v]) => ({
				label: k === 'job_id' ? 'Job' : (k.charAt(0).toUpperCase() + k.slice(1)).replaceAll('_', ' '),
				value: k.endsWith('_at') && typeof v === 'string' ? datetime(v) : String(v),
				href: k === 'job_id' ? `/jobs/${v}` : undefined
			}));
	}
	const resolutions: Record<string, string> = {
		cleared: 'The condition cleared by itself.',
		manual: 'Resolved by hand.',
		policy: 'Closed because its policy was changed, disabled or deleted.'
	};
</script>

<svelte:head>{#if res.data}<title>{res.data.title}</title>{/if}</svelte:head>

<Async {res}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-80" /></div>
		<div class="card space-y-2 p-4"><Skeleton lines={6} /></div>
	{/snippet}
	{#snippet children(a)}
		<PageHeader
			title={a.title}
			crumbs={[{ label: 'Alerts', href: '/alerts' }, { label: a.hostname, href: `/agents/${a.agent_id}?tab=alerts` }, { label: kindLabels[a.kind] }]}
			menu={[
				...(a.policy_id ? [{ label: 'Edit policy', icon: Pencil, href: `/policies/items/${a.policy_id}` }] : []),
				{ label: 'Copy alert ID', icon: Copy, onSelect: () => navigator.clipboard?.writeText(a.id).then(() => toast.success('Alert ID copied.')) }
			]}
		>
			{#snippet subtitle()}
				<SeverityBadge severity={a.severity} />
				<AlertStateBadge alert={a} />
				<span><a class="link" href="/agents/{a.agent_id}">{a.hostname}</a> · {a.client_name} › {a.site_name}</span>
			{/snippet}
			{#snippet actions()}
				{#if can('technician') && a.state !== 'resolved'}
					{#if a.state === 'open'}<Button icon={Check} onclick={() => act('acknowledge')}>Acknowledge</Button>{/if}
					<Button variant="primary" icon={CheckCheck} onclick={() => act('resolve')}>Resolve</Button>
				{/if}
			{/snippet}
		</PageHeader>

		<div class="grid gap-4 lg:grid-cols-[minmax(18rem,24rem)_1fr]">
			<section class="card self-start p-4" aria-label="Details">
				<h2 class="mb-3 panel-title">Details</h2>
				<dl class="dl">
					<dt>Policy</dt><dd>{#if a.policy_id}<a class="link" href="/policies/items/{a.policy_id}">{a.policy_name}</a>{:else}<span class="text-muted">Deleted</span>{/if}</dd>
					<dt>Type</dt><dd>{kindLabels[a.kind]}</dd>
					{#if a.ticket}<dt>Ticket</dt><dd><a class="link" href="/tickets/{a.ticket.id}">T-{a.ticket.number}</a></dd>{/if}
					<dt>Opened</dt><dd>{datetime(a.opened_at)} <span class="text-muted text-xs">({ago(a.opened_at)})</span></dd>
					<dt>Last seen</dt><dd>{datetime(a.last_seen_at)}</dd>
					{#if a.occurrences > 1}<dt>Occurrences</dt><dd class="tabular">{num(a.occurrences)}</dd>{/if}
					{#if a.acknowledged_at}<dt>Acknowledged</dt><dd>{datetime(a.acknowledged_at)}{#if a.acknowledged_by_name}<span class="text-muted block text-xs">by {a.acknowledged_by_name}</span>{/if}</dd>{/if}
					{#if a.resolved_at}
						<dt>Resolved</dt>
						<dd>{datetime(a.resolved_at)}<span class="text-muted block text-xs">{a.resolved_by_name ? `by ${a.resolved_by_name}` : resolutions[a.resolution ?? '']}</span></dd>
					{/if}
					{#each facts(a.details) as f (f.label)}
						<dt>{f.label}</dt><dd class="break-words">{#if f.href}<a class="link" href={f.href}>View job</a>{:else}{f.value}{/if}</dd>
					{/each}
				</dl>
			</section>

			<div class="min-w-0 space-y-4">
				<PageTimeline alertId={a.id} version={res.data ? Date.parse(a.acknowledged_at ?? a.resolved_at ?? a.opened_at) : 0} />
				{#if a.kind === 'log'}
					<section class="card" aria-label="Matched log entries">
						<header class="border-border flex items-center justify-between min-h-12 border-b px-4 py-3">
							<h2 class="panel-title">Matched entries</h2>
							<a class="link text-xs" href="/agents/{a.agent_id}?tab=logs">Event log</a>
						</header>
						{#if a.log_events.length}
							<ol class="divide-border divide-y">
								{#each a.log_events as e (e.id)}
									<li class="px-4 py-2.5 text-sm">
										<div class="text-muted mb-1 flex flex-wrap items-center gap-2 text-xs">
											<Badge tone={levelTone[e.level]}>{e.level}</Badge>
											<span class="font-medium">{e.source || '–'}</span>
											{#if e.event_id != null}<span>ID {e.event_id}</span>{/if}
											<time datetime={e.ts} title={datetime(e.ts)}>{ago(e.ts)}</time>
										</div>
										<pre class="font-mono text-xs break-words whitespace-pre-wrap">{e.message}</pre>
									</li>
								{/each}
							</ol>
						{:else}
							<EmptyState compact title="No entries kept" description="Matched entries are kept for 30 days." />
						{/if}
					</section>
				{/if}

				<section class="card" aria-label="Notifications">
					<header class="border-border min-h-12 border-b px-4 py-3"><h2 class="panel-title">Notifications</h2></header>
					{#if a.notifications.length}
						<ul class="divide-border divide-y">
							{#each a.notifications as n (n.id)}
								<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-sm">
									<Badge tone={n.status === 'sent' ? 'success' : n.status === 'failed' ? 'danger' : 'neutral'}>{n.status === 'pending' ? `Retrying (${n.attempts})` : n.status === 'sent' ? 'Sent' : 'Failed'}</Badge>
									<span class="font-medium">{n.channel_name}</span>
									<span class="text-muted">{n.event === 'opened' ? 'opened' : 'resolved'}</span>
									<span class="text-muted ml-auto text-xs" title={datetime(n.sent_at ?? n.created_at)}>{ago(n.sent_at ?? n.created_at)}</span>
									{#if n.last_error && n.status !== 'sent'}<p class="text-danger w-full text-xs break-words">{n.last_error}</p>{/if}
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact title="No notifications sent" description={a.policy_id ? 'This policy has no notification channels.' : undefined} />
					{/if}
				</section>
			</div>
		</div>
		{#if can('technician') && a.state !== 'resolved'}
			<!-- Phones: the actions stay in reach while scrolling. -->
			<div class="bg-surface border-border sticky bottom-[var(--bottom-bar,0px)] z-30 -mx-3 mt-4 flex gap-2 border-t px-3 py-2 sm:hidden">
				{#if a.state === 'open'}<Button class="min-h-11 flex-1" icon={Check} onclick={() => act('acknowledge')}>Acknowledge</Button>{/if}
				<Button class="min-h-11 flex-1" variant="primary" icon={CheckCheck} onclick={() => act('resolve')}>Resolve</Button>
			</div>
		{/if}
	{/snippet}
</Async>
