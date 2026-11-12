<script lang="ts">
	import { CircleAlert, OctagonAlert } from '@lucide/svelte';
	import type { AgentSummary, Health } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/**
	 * Health from the last report (disks, failed jobs, update failures, patches, alerts), separate from
	 * online/offline. Colour is spent on exceptions only: Healthy and "No data" are plain muted
	 * text, so a row that needs a look is the one with a fill.
	 */
	let { health, agent }: { health: Health; agent?: Pick<AgentSummary, 'disk_max_pct' | 'failed_jobs_24h' | 'update_state'> & Partial<Pick<AgentSummary, 'open_alerts' | 'patches_overdue' | 'patches_failed' | 'reboot_pending' | 'reboot_pending_since'>> } = $props();
	const why = $derived.by(() => {
		if (!agent) return undefined;
		const r: string[] = [];
		if (agent.disk_max_pct >= 90) r.push(`disk ${agent.disk_max_pct.toFixed(0)}% full`);
		if (agent.failed_jobs_24h) r.push(`${agent.failed_jobs_24h} failed job${agent.failed_jobs_24h === 1 ? '' : 's'} today`);
		if (agent.update_state === 'failed' || agent.update_state === 'rolled_back') r.push(`agent update ${agent.update_state.replace('_', ' ')}`);
		if (agent.patches_overdue) r.push(`${agent.patches_overdue} security update${agent.patches_overdue === 1 ? '' : 's'} missing over a week`);
		if (agent.patches_failed) r.push(`${agent.patches_failed} update${agent.patches_failed === 1 ? '' : 's'} failed to install`);
		if (agent.reboot_pending && agent.reboot_pending_since && Date.now() - Date.parse(agent.reboot_pending_since) > 864e5) r.push('restart pending over a day');
		if (agent.open_alerts) r.push(`${agent.open_alerts} open alert${agent.open_alerts === 1 ? '' : 's'}`);
		return r.join(', ') || undefined;
	});
</script>

{#if health === 'attention'}
	<Badge tone="warning" icon={CircleAlert} title={why}>Needs attention</Badge>
{:else if health === 'unhealthy'}
	<Badge tone="danger" icon={OctagonAlert} title={why}>Unhealthy</Badge>
{:else}
	<span class="text-muted inline-flex h-5 items-center leading-5 whitespace-nowrap">{health === 'healthy' ? 'Healthy' : 'No data'}</span>
{/if}
