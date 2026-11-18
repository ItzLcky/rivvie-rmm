<script lang="ts">
	import type { Snippet } from 'svelte';
	import { ago, bytes, datetime, num, plural } from '#lib/format.js';
	import { databaseStale, micros, rate, realtimeView } from '#lib/security.js';
	import type { AgentDatabase, SecurityProduct, SensorPolicy, SensorStatus } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** Our own sensor on one agent: whether it runs, its content and health, and the policy it follows. */
	let {
		sensor,
		policy,
		product,
		reportedAt,
		actions,
		os,
		database = null,
		maxAgeHours = 0
	}: {
		sensor: SensorStatus | null;
		policy: SensorPolicy;
		/** The sensor as a protection product (scan times, scan actions), when it reports one. */
		product?: SecurityProduct;
		reportedAt: string | null;
		/** Scan buttons. */
		actions?: Snippet;
		/** The agent's OS family: real-time protection exists on Linux only. */
		os: string;
		/** The signature database it runs, as the server has it. */
		database?: AgentDatabase | null;
		/** The policy's limit on the database's age, hours (0: none). */
		maxAgeHours?: number;
	} = $props();

	const h = $derived(sensor?.health ?? null);
	const restarting = $derived(!!sensor?.running && sensor.restarts >= 3);
	const rt = $derived(h?.realtime ?? null);
	const rtView = $derived(realtimeView(rt, os, !!sensor?.running, policy.prevention));
	const dbVersion = $derived(h?.database_version ?? sensor?.database_version ?? null);
	const stale = $derived(databaseStale(database?.built_at, maxAgeHours));
	const hitRate = $derived(h ? rate(h.cache_hits ?? 0, h.files_scanned ?? 0) : null);
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
			{#if rtView}
				<dt>Real-time</dt>
				<dd>
					{#if rtView.fault}<Badge tone="warning">{rtView.label}</Badge>{:else if rt?.mode === 'off' || os !== 'linux'}<span class="text-muted">{rtView.label}</span>{:else}{rtView.label}{/if}
					{#if rtView.detail}<span class="text-muted block text-xs break-words">{rtView.detail}</span>{/if}
				</dd>
				{#if rt && rt.state === 'on'}
					<dt>On access</dt>
					<dd class="tabular text-sm">
						{num(rt.decisions)} decided <span class="text-muted">·</span> {#if rt.denied}<span class="font-semibold">{num(rt.denied)} denied</span>{:else}0 denied{/if}
						<span class="text-muted block text-xs">
							{rate(rt.cache_hits, rt.decisions - rt.cache_hits) ?? 0}% from the cache · p50 {micros(rt.p50_us)}, p99 {micros(rt.p99_us)}
						</span>
						{#if rt.timeouts || rt.overloaded}
							<span class="mt-0.5 flex flex-wrap gap-1">
								{#if rt.timeouts}<Badge tone="warning" title="Allowed at the 500 ms deadline, then scanned in the background">{plural(rt.timeouts, 'timeout')}</Badge>{/if}
								{#if rt.overloaded}<Badge tone="warning" title="Allowed at once because every worker was busy, then scanned in the background">{num(rt.overloaded)} overloaded</Badge>{/if}
							</span>
						{:else}
							<span class="text-muted block text-xs">No timeouts, no overload</span>
						{/if}
					</dd>
					{#if rt.scan_on_write}
						<dt>Written files</dt>
						<dd class="tabular text-sm">{num(rt.write_scans)} scanned{#if rt.write_dropped}{' '}<Badge tone="warning" title="Not scanned: the queue was full">{num(rt.write_dropped)} dropped</Badge>{/if}</dd>
					{/if}
				{/if}
			{/if}
			<dt>Signatures</dt>
			<dd>
				{#if dbVersion}
					<span class="font-mono text-xs">{dbVersion}</span>
					{#if database}
						<span class="text-muted text-xs">{' · built '}<span title={datetime(database.built_at)}>{ago(database.built_at)}</span></span>
						{#if stale}<Badge tone="warning" title="Older than the policy's {maxAgeHours} hours">Out of date</Badge>{/if}
					{/if}
					{#if h && (h.hash_signatures || h.yara_rules)}<span class="text-muted block text-xs">{plural(h.hash_signatures ?? 0, 'hash', 'hashes')}, {plural(h.yara_rules ?? 0, 'YARA rule')}</span>{/if}
				{:else}
					<span class="text-muted">No signature database yet</span>
				{/if}
			</dd>
			{#if h && (h.files_scanned || h.cache_hits)}
				<dt>Files scanned</dt>
				<dd class="tabular text-sm">{num(h.files_scanned ?? 0)} read{#if hitRate !== null}<span class="text-muted text-xs">{' · '}{num(h.cache_hits ?? 0)} skipped as unchanged ({hitRate}%)</span>{/if}</dd>
			{/if}
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
	{#if reportedAt}<p class="text-muted mt-3 text-xs">Reported <span title={datetime(reportedAt)}>{ago(reportedAt)}</span>; counts are since the sensor started. The security policy sets these; change it under Security › Settings.</p>{/if}
</section>
