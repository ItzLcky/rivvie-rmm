<script lang="ts">
	import { Download } from '@lucide/svelte';
	import { ago, datetime } from '#lib/format.js';
	import { actionStatusLabels, actionStatusTone, actionTarget, actionTitle, productLabels, responseActions } from '#lib/security.js';
	import type { ResponseActionName, SecurityActionRow } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';

	/** Scans, updates and response actions, newest first, with a Download link for triage packages. */
	let { actions, title = 'Actions', emptyTitle = 'Nothing started from here yet' }: { actions: SecurityActionRow[]; title?: string; emptyTitle?: string } = $props();
	const isResponse = (a: SecurityActionRow) => responseActions.includes(a.action as ResponseActionName);
</script>

<section class="card" aria-label={title}>
	<header class="border-border min-h-12 border-b px-4 py-3"><h2 class="panel-title">{title}</h2></header>
	{#if actions.length}
		<ol class="divide-border divide-y">
			{#each actions as a (a.id)}
				{@const target = actionTarget(a)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
					<Badge tone={actionStatusTone[a.status]}>{actionStatusLabels[a.status]}</Badge>
					<div class="min-w-0 flex-1 basis-56">
						<span class="font-medium">{actionTitle(a)}</span>
						{#if !isResponse(a)}<span class="text-muted">{' · '}{productLabels[a.product] ?? a.product}</span>{/if}
						{#if target}<div class="text-muted font-mono text-xs break-all">{target}</div>{/if}
						{#if a.message}<div class="text-muted text-xs break-words">{a.message}</div>{/if}
					</div>
					<div class="ml-auto flex items-center gap-3">
						{#if a.has_download}
							<Button size="xs" icon={Download} href="/api/security/actions/{a.id}/download" download>Download</Button>
						{/if}
						<span class="text-muted text-xs whitespace-nowrap">{a.created_by_name ?? 'System'} · <time datetime={a.created_at} title={datetime(a.created_at)}>{ago(a.created_at)}</time></span>
					</div>
				</li>
			{/each}
		</ol>
	{:else}
		<EmptyState compact title={emptyTitle} />
	{/if}
</section>
