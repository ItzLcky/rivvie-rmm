<script lang="ts">
	import type { Snippet } from 'svelte';
	import { ago, bytes, datetime, num, plural } from '#lib/format.js';
	import type { SecurityProduct, SensorPolicy, SensorStatus } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** Our own sensor on one agent: whether it runs, its content and health, and the policy it follows. */
	let {
		sensor,
		policy,
		product,
		reportedAt,
		actions
	}: {
		sensor: SensorStatus | null;
		policy: SensorPolicy;
		/** The sensor as a protection product (scan times, scan actions), when it reports one. */
		product?: SecurityProduct;
		reportedAt: string | null;
		/** Scan buttons. */
		actions?: Snippet;
	} = $props();

	const h = $derived(sensor?.health ?? null);
	const restarting = $derived(!!sensor?.running && sensor.restarts >= 3);
</script>

{#snippet onOff(v: boolean)}{#if v}On{:else}<span class="text-muted">Off</span>{/if}{/snippet}

<section class="card p-4" aria-labelledby="sensor-h">
	<div class="mb-3 flex flex-wrap items-start justify-between gap-2">
		<div class="min-w-0">
			<h2 id="sensor-h" class="panel-title">RMM sensor</h2>
			<div class="text-muted text-xs">Our own detection and response, built into the agent</div>
		</div>
		{@render actions?.()}
	</div>
	<dl class="dl">
		<dt>State</dt>
		<dd>
			{#if !policy.enabled}
				<span class="text-muted">Off by policy</span>
			{:else if !sensor}
				<span class="text-muted">Waiting for its first report</span>
			{:else if !sensor.running}
				<Badge tone="danger">Not running</Badge>
			{:else if restarting}
				<Badge tone="warning">Keeps restarting</Badge>
			{:else}
				Running
			{/if}
			{#if sensor && sensor.restarts > 0}<span class="text-muted text-xs">{' · '}{plural(sensor.restarts, 'restart')} since the agent started</span>{/if}
		</dd>
		{#if sensor?.error}
			<dt>Problem</dt>
			<dd class="text-danger break-words">{sensor.error}</dd>
		{/if}
		{#if policy.enabled}
			<dt>Content</dt>
			<dd>
				{#if sensor?.content_version}<span class="font-mono text-xs">{sensor.content_version}</span>{:else}<span class="text-muted">None yet</span>{/if}
				{#if h}<span class="text-muted text-xs">{' · '}{plural(h.rules, 'rule')} loaded</span>{/if}
			</dd>
			{#if h}
				<dt>Events</dt>
				<dd class="tabular">{num(Math.round(h.events_per_min))} a minute <span class="text-muted text-xs">· {num(h.events_total)} recorded, {bytes(h.store_bytes)} stored</span></dd>
				<dt>Resources</dt>
				<dd class="tabular">{h.cpu_percent.toFixed(1)}% CPU <span class="text-muted">·</span> {bytes(h.rss_bytes)} memory</dd>
				{#if h.collectors.length}
					<dt>Collectors</dt>
					<dd class="flex flex-wrap gap-x-3 gap-y-0.5 text-xs">
						{#each h.collectors as [name, how] (name)}<span>{name} <span class="text-muted font-mono">{how}</span></span>{/each}
					</dd>
				{/if}
				<dt>Last scan</dt>
				<dd>{#if h.last_scan}<span title={datetime(h.last_scan)}>{ago(h.last_scan)}</span>{:else}<span class="text-muted">Never</span>{/if}</dd>
			{:else if product?.last_quick_scan_at}
				<dt>Last scan</dt>
				<dd><span title={datetime(product.last_quick_scan_at)}>{ago(product.last_quick_scan_at)}</span></dd>
			{/if}
			<dt>Prevention</dt>
			<dd>{@render onOff(policy.prevention)} <span class="text-muted text-xs">· {policy.prevention ? 'block-mode rules stop what they detect' : 'detects and alerts only'}</span></dd>
			<dt>Auto-quarantine</dt>
			<dd>{@render onOff(policy.auto_quarantine)}</dd>
			<dt>Scheduled scans</dt>
			<dd class="text-sm">
				{policy.quick_scan_hours ? `Quick every ${plural(policy.quick_scan_hours, 'hour')}` : 'No quick scans'}<span class="text-muted">,</span>
				{policy.full_scan_days ? `full every ${plural(policy.full_scan_days, 'day')}` : 'no full scans'}
			</dd>
			<dt>Ransomware decoys</dt>
			<dd>{@render onOff(policy.canaries)}{#if h && policy.canaries}<span class="text-muted text-xs">{' · '}{plural(h.canaries, 'file')} in place</span>{/if}</dd>
			{#if policy.exclusions.length}
				<dt>Exclusions</dt>
				<dd class="text-muted text-xs">{plural(policy.exclusions.length, 'exclusion')} apply here</dd>
			{/if}
		{/if}
	</dl>
	{#if reportedAt}<p class="text-muted mt-3 text-xs">Reported <span title={datetime(reportedAt)}>{ago(reportedAt)}</span>. The security policy sets these; change it under Security › Settings.</p>{/if}
</section>
