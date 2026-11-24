<script lang="ts">
	import { api } from '#lib/api.js';
	import { ago, bytes, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { backupLabel, backupTone, providerLabels, type BackupJob } from '#lib/uptime.js';
	import Badge from '#lib/ui/Badge.svelte';
	import MoreLink from '#lib/ui/MoreLink.svelte';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';

	/** The device's backup jobs, as it last reported them. Shows nothing while it has none. */
	let { agentId }: { agentId: string } = $props();
	const jobs = resource(() => api.get<BackupJob[]>(`/agents/${agentId}/backups`));
	async function readNow() {
		await attempt(() => api.post(`/agents/${agentId}/backups/check`), 'Asked the device to read its backups.');
	}
	liveReload(() => jobs.reload(), (e) => e.type === 'backups' && e.agent_id === agentId, { debounceMs: 1000 });
</script>

{#if jobs.data?.length}
	<section class="card" aria-label="Backups">
		<header class="border-border flex min-h-12 items-center justify-between border-b px-4 py-3">
			<h2 class="panel-title">Backups</h2>
			<div class="flex items-center gap-3">
				{#if can('technician')}<button type="button" class="text-muted hover:text-fg text-xs font-medium" onclick={readNow}>Read now</button>{/if}
				<MoreLink href="/backups?q={encodeURIComponent(jobs.data[0].hostname)}">All backups</MoreLink>
			</div>
		</header>
		<ul class="divide-border divide-y">
			{#each jobs.data as j (`${j.provider}/${j.job}`)}
				<li class="flex items-start gap-3 px-4 py-2 text-sm">
					<div class="min-w-0 flex-1">
						<div class="truncate font-medium" title={j.job}>{j.job}</div>
						<div class="text-muted text-xs">
							{providerLabels[j.provider] ?? j.provider}
							· last success <span title={datetime(j.last_success_at)}>{j.last_success_at ? ago(j.last_success_at) : 'never'}</span>{j.size_bytes ? ` · ${bytes(j.size_bytes)}` : ''}
						</div>
						{#if j.message && j.last_result !== 'success'}<div class="text-muted truncate text-xs" title={j.message}>{j.message}</div>{/if}
					</div>
					<Badge tone={backupTone[j.last_result]}>{backupLabel[j.last_result]}</Badge>
				</li>
			{/each}
		</ul>
	</section>
{/if}
