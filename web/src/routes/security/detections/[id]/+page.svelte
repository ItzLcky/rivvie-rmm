<script lang="ts">
	import { page } from '$app/state';
	import { BellRing, Check, Copy, ExternalLink, FileX2, History, Network, PackageOpen, RotateCcw, Search, ShieldQuestion, Skull, Unplug, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, cx, datetime, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import {
		confidenceLabels, eventKindLabels, mitreUrl, modeLabels, productLabels, resourceLabel, severityLabels, severityTone, sourceLabels, splitContext,
		threatStatusLabels, threatStatusTone, verdictLabels, verdictTone
	} from '#lib/security.js';
	import { allowed } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { DetectionDetail, Proc, TelemetryEvent, TelemetryResult, Verdict } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import Status from '#lib/components/Status.svelte';
	import ActionHistory from '#lib/components/security/ActionHistory.svelte';
	import EventTable from '#lib/components/security/EventTable.svelte';
	import RespondDialog, { type RespondKind } from '#lib/components/security/RespondDialog.svelte';
	import RestoreDialog from '#lib/components/security/RestoreDialog.svelte';

	const id = $derived(page.params.id!);
	const res = resource(() => api.get<DetectionDetail>(`/security/detections/${id}`), { keep: false });
	liveReload(() => res.reload(), (e) => e.type === 'security' && e.agent_id === res.data?.agent_id, { debounceMs: 500 });

	const canRespond = $derived(allowed('security.respond'));
	const canManage = $derived(allowed('security.manage'));

	// --- Context: process tree and timeline -----------------------------------------------------
	const ctx = $derived(splitContext(res.data?.context ?? []));
	/** Root first, ending with the detected process. */
	const tree = $derived.by((): { proc: Proc; detected: boolean }[] => {
		const t = ctx.trigger;
		if (!t?.process) return [];
		const up = ctx.ancestors.map((e) => e.process).filter((p): p is Proc => !!p).reverse();
		if (!up.length && t.parent) up.push(t.parent);
		return [...up.map((proc) => ({ proc, detected: false })), { proc: t.process, detected: true }];
	});
	let around = $state<TelemetryResult | null>(null);
	let loadingAround = $state(false);
	const timeline = $derived.by(() => {
		const seen = new Set<number>();
		const all = [...(ctx.trigger ? [ctx.trigger] : []), ...ctx.related, ...(around?.events ?? [])];
		return all.filter((e) => (seen.has(e.seq) ? false : (seen.add(e.seq), true))).sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.seq - b.seq);
	});
	async function loadAround(d: DetectionDetail) {
		loadingAround = true;
		try {
			around = await api.get<TelemetryResult>(`/agents/${d.agent_id}/telemetry${qs({ around: d.detected_at ?? d.first_seen_at, window: 10, limit: 500 })}`);
			if (around.error) toast.error(`The agent answered with a problem: ${around.error}`);
		} catch (err) {
			toast.error(err);
		} finally {
			loadingAround = false;
		}
	}
	const isTrigger = (e: TelemetryEvent) => !!ctx.trigger && e.seq === ctx.trigger.seq;

	// --- Response -------------------------------------------------------------------------------
	let responding = $state<{ kind: RespondKind; pid?: number; path?: string; processName?: string } | null>(null);
	let restoring = $state(false);
	/** The file to quarantine: the event's file, else the first file resource (never a process image: that could be powershell.exe). */
	function filePath(d: DetectionDetail): string | null {
		if (ctx.trigger?.file?.path) return ctx.trigger.file.path;
		const r = d.resources.find((x) => /^file:_/i.test(x) || /^[a-z]:\\|^\//i.test(x));
		return r ? resourceLabel(r) : null;
	}

	// --- Verdict --------------------------------------------------------------------------------
	let notes = $state<string | null>(null);
	let exclude = $state<'' | 'sha256' | 'rule'>('');
	let saving = $state<Verdict | 'reopen' | null>(null);
	async function setVerdict(d: DetectionDetail, verdict: Verdict | null) {
		saving = verdict ?? 'reopen';
		try {
			await api.post(`/security/detections/${d.id}/verdict`, {
				verdict,
				notes: (notes ?? d.notes ?? '').trim(),
				exclude: verdict === 'false_positive' && canManage && exclude ? exclude : undefined
			});
			toast.success(
				verdict
					? `Marked as ${verdictLabels[verdict].toLowerCase()}.${verdict === 'false_positive' && exclude ? ` The ${exclude === 'sha256' ? 'file’s hash' : 'rule'} is excluded for ${d.client_name}.` : ''}`
					: 'Reopened.'
			);
			notes = null;
			exclude = '';
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			saving = null;
		}
	}

	function copyId(d: DetectionDetail) {
		navigator.clipboard?.writeText(d.id).then(() => toast.success('Detection ID copied.'));
	}
</script>

<svelte:head>{#if res.data}<title>{res.data.name}</title>{/if}</svelte:head>

{#snippet procLine(p: Proc)}
	<div class="flex flex-wrap items-baseline gap-x-2">
		<span class="font-medium break-all">{p.name}</span>
		<span class="text-muted text-xs tabular">PID {p.pid}</span>
		{#if p.user}<span class="text-muted text-xs break-all">{p.user}</span>{/if}
		{#if p.started_at}<span class="text-muted text-xs" title={datetime(p.started_at)}>started {ago(p.started_at)}</span>{/if}
	</div>
	{#if p.command_line}<div class="font-mono text-xs break-all">{p.command_line}</div>{/if}
	{#if p.exe && !p.command_line.toLowerCase().includes(p.exe.toLowerCase())}<div class="text-muted font-mono text-xs break-all">{p.exe}</div>{/if}
	{#if p.sha256}<div class="text-muted font-mono text-[11px] break-all">SHA-256 {p.sha256}</div>{/if}
{/snippet}

<Async {res}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-80" /></div>
		<div class="grid gap-4 lg:grid-cols-[1fr_22rem]"><div class="card p-4"><Skeleton lines={8} /></div><div class="card p-4"><Skeleton lines={6} /></div></div>
	{/snippet}
	{#snippet children(d)}
		{@const active = !d.resolved_at && d.status === 'active' && !d.audit}
		{@const path = filePath(d)}
		{@const triggerProc = ctx.trigger?.process}
		<PageHeader
			title={d.name}
			crumbs={[{ label: 'Security', href: '/security' }, { label: 'Detections', href: '/security?tab=detections&view=all' }, { label: d.hostname, href: `/agents/${d.agent_id}?tab=security` }]}
			menu={[
				...(d.alert ? [{ label: 'Open the alert', icon: BellRing, href: `/alerts/${d.alert.id}` }] : []),
				...(d.sha256 ? [{ label: 'Hunt for this file', icon: Search, href: `/security${qs({ tab: 'hunt', sha256: d.sha256 })}` }] : []),
				{ label: 'Copy detection ID', icon: Copy, onSelect: () => copyId(d) }
			]}
		>
			{#snippet subtitle()}
				<Badge tone={severityTone[d.severity]}>{severityLabels[d.severity]}</Badge>
				<Badge tone={active ? 'danger' : d.audit ? 'neutral' : threatStatusTone[d.status]}>{d.audit && d.status === 'active' ? 'Recorded' : threatStatusLabels[d.status]}</Badge>
				{#if d.verdict}<Badge tone={verdictTone[d.verdict]}>{verdictLabels[d.verdict]}</Badge>{/if}
				{#if d.audit}<Badge title="Recorded by a rule in audit mode: no alert and no action were taken">Audit only</Badge>{/if}
				{#if d.isolated}<Badge tone="danger" icon={Network}>Isolated</Badge>{/if}
				<span class="inline-flex flex-wrap items-center gap-x-2">
					<a class="link" href="/agents/{d.agent_id}?tab=security">{d.hostname}</a>
					<Status online={d.online} />
					<span>{d.client_name} › {d.site_name}</span>
				</span>
			{/snippet}
			{#snippet actions()}
				{#if d.alert}<Button icon={BellRing} href="/alerts/{d.alert.id}">Alert{d.alert.state === 'resolved' ? ' (resolved)' : ''}</Button>{/if}
			{/snippet}
		</PageHeader>

		{#if d.audit}
			<p class="border-border bg-sunken text-muted mb-4 rounded-md border px-3 py-2 text-sm" role="status">
				The rule that found this is in audit mode: it was recorded, but nothing was blocked and no alert was raised. Use what you see here to decide whether the rule can be switched to alert or block.
			</p>
		{/if}

		<div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,22rem)]">
			<div class="min-w-0 space-y-4">
				<!-- Process tree -->
				<section class="card" aria-labelledby="tree-h">
					<header class="border-border min-h-12 border-b px-4 py-3">
						<h2 id="tree-h" class="panel-title">Process tree</h2>
						<p class="text-muted text-xs">How the detected process was started, from the oldest ancestor down.</p>
					</header>
					{#if d.context_unavailable}
						<EmptyState compact icon={ShieldQuestion} title="Context isn’t readable on this server" description="The agent encrypted it with a key this server doesn’t have (it was restored or moved). The detection itself is intact." />
					{:else if tree.length}
						<ol class="space-y-0 p-3" aria-label="Processes, root first">
							{#each tree as node, i (i)}
								<li class="relative" style="padding-left: min({i * 1.25}rem, {i * 6}vw)">
									{#if i > 0}<span class="text-subtle absolute top-2.5 font-mono text-xs" style="left: calc(min({i * 1.25}rem, {i * 6}vw) - 1rem)" aria-hidden="true">└</span>{/if}
									<div class={cx('my-1 min-w-0 rounded-md border px-3 py-2', node.detected ? 'border-danger/50 bg-danger-soft/50' : 'border-transparent')}>
										{#if node.detected}<div class="text-danger mb-0.5 text-xs font-semibold">Detected</div>{/if}
										{@render procLine(node.proc)}
									</div>
								</li>
							{/each}
						</ol>
					{:else if ctx.trigger}
						<p class="text-muted px-4 py-3 text-sm">This was a {eventKindLabels[ctx.trigger.kind]?.toLowerCase() ?? ctx.trigger.kind} event with no process attached.</p>
					{:else}
						<EmptyState
							compact
							title="No process context"
							description={d.source === 'product'
								? 'The antivirus reported this; it doesn’t send process context. Load the events around the time from the timeline below.'
								: d.source === 'file'
									? 'A scan found this file on disk; no running process was involved. The timeline shows what touched it.'
									: 'The agent sent no context with this detection.'}
						/>
					{/if}
				</section>

				<!-- Timeline -->
				<section class="card" aria-labelledby="timeline-h">
					<header class="border-border flex flex-wrap items-center gap-x-3 gap-y-2 min-h-12 border-b px-4 py-3">
						<div class="min-w-0 flex-1">
							<h2 id="timeline-h" class="panel-title">Timeline</h2>
							<p class="text-muted text-xs">{around ? `The detection’s context plus ${plural(around.events.length, 'event')} from the 10 minutes either side${around.truncated ? ' (more were left out)' : ''}.` : 'What the process tree did around the detection.'}</p>
						</div>
						<Button size="sm" icon={History} loading={loadingAround} disabled={!d.online} title={d.online ? undefined : 'The agent is offline; its telemetry stays on the machine'} onclick={() => loadAround(d)}>
							{around ? 'Reload events around this time' : 'Load events around this time'}
						</Button>
					</header>
					{#if timeline.length}
						<EventTable events={timeline} caption="Timeline" highlight={isTrigger} />
					{:else}
						<EmptyState compact title="No events yet" description={d.online ? 'Load the events around this time to see what else happened on the machine.' : 'The agent is offline; its telemetry can be loaded once it reconnects.'} />
					{/if}
				</section>

				<!-- Prevalence -->
				<section class="card" aria-labelledby="prev-h">
					<header class="border-border min-h-12 border-b px-4 py-3">
						<h2 id="prev-h" class="panel-title">Seen elsewhere</h2>
						<p class="text-muted text-xs">Other machines with the same file, from detections and quarantine. Hunting also asks the agents’ telemetry.</p>
					</header>
					{#if !d.sha256}
						<p class="text-muted px-4 py-3 text-sm">This detection has no file hash to compare.</p>
					{:else if d.prevalence.length}
						<ul class="divide-border divide-y">
							{#each d.prevalence as p (p.agent_id + p.how)}
								<li class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-4 py-2 text-sm">
									<a class="hover:text-accent font-medium" href="/agents/{p.agent_id}?tab=security">{p.hostname}</a>
									<span class="text-muted text-xs">{p.client_name}</span>
									<span class="text-muted min-w-0 flex-1 text-xs">{p.how}</span>
									<span class="text-muted text-xs" title={datetime(p.first_seen)}>first {ago(p.first_seen)}</span>
								</li>
							{/each}
						</ul>
					{:else}
						<p class="text-muted px-4 py-3 text-sm">Only seen on {d.hostname}.</p>
					{/if}
				</section>

				<ActionHistory actions={d.actions} title="Responses to this detection" emptyTitle="Nothing done from this detection yet" />
			</div>

			<div class="min-w-0 space-y-4">
				<!-- Respond -->
				{#if canRespond}
					<section class="card p-4" aria-labelledby="respond-h">
						<h2 id="respond-h" class="mb-1 panel-title">Respond</h2>
						<p class="text-muted mb-3 text-xs">{d.online ? `Each action asks first, then runs on ${d.hostname}.` : `${d.hostname} is offline; responses need the agent connected.`}</p>
						<div class="grid gap-1.5">
							{#if triggerProc}
								<Button class="justify-start" icon={Skull} disabled={!d.online} onclick={() => (responding = { kind: 'kill_process', pid: triggerProc.pid, processName: triggerProc.command_line || triggerProc.name })}>Kill process tree</Button>
							{/if}
							{#if d.quarantine_id}
								<Button class="justify-start" icon={RotateCcw} disabled={!d.online} onclick={() => (restoring = true)}>Restore the file…</Button>
							{:else if path}
								<Button class="justify-start" icon={FileX2} disabled={!d.online} onclick={() => (responding = { kind: 'quarantine_file', path })}>Quarantine the file</Button>
							{/if}
							{#if d.isolated}
								<Button class="justify-start" icon={Network} disabled={!d.online} onclick={() => (responding = { kind: 'release' })}>Release from isolation</Button>
							{:else}
								<Button class="justify-start" icon={Unplug} disabled={!d.online} onclick={() => (responding = { kind: 'isolate' })}>Isolate network</Button>
							{/if}
							<Button class="justify-start" icon={PackageOpen} disabled={!d.online} onclick={() => (responding = { kind: 'collect_triage' })}>Collect triage package</Button>
						</div>
					</section>

					<!-- Verdict -->
					<section class="card p-4" aria-labelledby="verdict-h">
						<h2 id="verdict-h" class="mb-1 panel-title">Verdict</h2>
						{#if d.verdict}
							<p class="mb-3 text-sm">
								<Badge tone={verdictTone[d.verdict]}>{verdictLabels[d.verdict]}</Badge>
								<span class="text-muted text-xs">{d.verdict_by_name ?? 'Someone'}{d.verdict_at ? `, ${ago(d.verdict_at)}` : ''}</span>
							</p>
						{:else}
							<p class="text-muted mb-3 text-xs">What was it? Verdicts feed each rule’s false-positive rate, which decides when it can block.</p>
						{/if}
						<Field label="Notes" id="v-notes" class="mb-3">
							<Textarea id="v-notes" rows={3} value={notes ?? d.notes ?? ''} oninput={(e) => (notes = e.currentTarget.value)} placeholder="What you found, what you did" />
						</Field>
						{#if canManage && (d.sha256 || d.rule_id)}
							<Field label="If it’s a false positive, also exclude" id="v-exclude" class="mb-3" hint="For {d.client_name} only. Manage exclusions under Security › Settings.">
								<Select
									id="v-exclude"
									class="w-full"
									bind:value={exclude}
									options={[
										{ value: '', label: 'Nothing' },
										...(d.sha256 ? [{ value: 'sha256' as const, label: 'This file’s hash' }] : []),
										...(d.rule_id ? [{ value: 'rule' as const, label: `The rule ${d.rule_id}` }] : [])
									]}
								/>
							</Field>
						{/if}
						<div class="flex flex-wrap gap-1.5">
							<Button size="sm" variant={d.verdict === 'true_positive' ? 'primary' : 'secondary'} icon={Check} loading={saving === 'true_positive'} disabled={saving !== null} onclick={() => setVerdict(d, 'true_positive')}>True positive</Button>
							<Button size="sm" variant={d.verdict === 'false_positive' ? 'primary' : 'secondary'} icon={X} loading={saving === 'false_positive'} disabled={saving !== null} onclick={() => setVerdict(d, 'false_positive')}>False positive</Button>
							<Button size="sm" variant={d.verdict === 'benign' ? 'primary' : 'secondary'} loading={saving === 'benign'} disabled={saving !== null} onclick={() => setVerdict(d, 'benign')}>Benign</Button>
							{#if d.verdict}<Button size="sm" variant="ghost" icon={RotateCcw} loading={saving === 'reopen'} disabled={saving !== null} onclick={() => setVerdict(d, null)}>Reopen</Button>{/if}
						</div>
					</section>
				{:else if d.verdict || d.notes}
					<section class="card p-4" aria-labelledby="verdict-h">
						<h2 id="verdict-h" class="mb-2 panel-title">Verdict</h2>
						{#if d.verdict}<p class="mb-2 text-sm"><Badge tone={verdictTone[d.verdict]}>{verdictLabels[d.verdict]}</Badge> <span class="text-muted text-xs">{d.verdict_by_name ?? ''}{d.verdict_at ? `, ${ago(d.verdict_at)}` : ''}</span></p>{/if}
						{#if d.notes}<p class="text-sm break-words whitespace-pre-line">{d.notes}</p>{/if}
					</section>
				{/if}

				<!-- Details -->
				<section class="card p-4" aria-labelledby="details-h">
					<h2 id="details-h" class="mb-3 panel-title">Details</h2>
					<dl class="dl">
						<dt>Found by</dt>
						<dd>{productLabels[d.product]}{#if d.product === 'rmm'}<span class="text-muted">{' · '}{sourceLabels[d.source]}</span>{/if}</dd>
						<dt>Detected</dt>
						<dd><span title={datetime(d.detected_at ?? d.first_seen_at)}>{ago(d.detected_at ?? d.first_seen_at)}</span>{#if d.last_seen_at !== d.first_seen_at}<span class="text-muted block text-xs">last reported {ago(d.last_seen_at)}</span>{/if}</dd>
						{#if d.resolved_at}<dt>Resolved</dt><dd><span title={datetime(d.resolved_at)}>{ago(d.resolved_at)}</span></dd>{/if}
						{#if d.action_taken}<dt>Action taken</dt><dd>{d.action_taken}</dd>{/if}
						{#if d.username}<dt>User</dt><dd class="break-all">{d.username}</dd>{/if}
						{#if d.process}<dt>Process</dt><dd class="font-mono text-xs break-all">{d.process}</dd>{/if}
						{#if d.sha256}
							<dt>SHA-256</dt>
							<dd class="flex items-start gap-1"><span class="min-w-0 font-mono text-xs break-all">{d.sha256}</span><CopyButton text={d.sha256} label="Copy hash" /></dd>
						{/if}
						{#if d.content_version}<dt>Content</dt><dd class="font-mono text-xs">{d.content_version}</dd>{/if}
					</dl>
					{#if d.resources.length}
						<h3 class="text-muted mt-4 mb-1 text-xs font-medium">Resources</h3>
						<ul class="space-y-1">
							{#each d.resources as r (r)}<li class="font-mono text-xs break-all">{resourceLabel(r)}</li>{/each}
						</ul>
					{/if}
				</section>

				<!-- Rule -->
				{#if d.rule || d.rule_id || d.mitre.length}
					<section class="card p-4" aria-labelledby="rule-h">
						<h2 id="rule-h" class="mb-1 panel-title">{d.rule?.name ?? 'Rule'}</h2>
						{#if d.rule?.description}<p class="text-muted mb-3 text-sm">{d.rule.description}</p>{/if}
						<dl class="dl">
							{#if d.rule_id}<dt>Rule</dt><dd class="font-mono text-xs">{d.rule_id}</dd>{/if}
							{#if d.rule}
								<dt>Kind</dt><dd>{d.rule.kind === 'file' ? 'File signature' : `Behaviour${d.rule.event ? ` (${eventKindLabels[d.rule.event]?.toLowerCase() ?? d.rule.event} events)` : ''}`}</dd>
								<dt>Confidence</dt><dd>{confidenceLabels[d.rule.confidence] ?? d.rule.confidence}</dd>
								<dt>Mode</dt><dd>{modeLabels[d.rule.mode] ?? d.rule.mode} <span class="text-muted text-xs">(as shipped)</span></dd>
							{/if}
							{#if d.mitre.length}
								<dt>MITRE ATT&amp;CK</dt>
								<dd class="flex flex-wrap gap-x-3 gap-y-1">
									{#each d.mitre as t (t)}
										<a class="link inline-flex items-center gap-0.5 font-mono text-xs" href={mitreUrl(t)} target="_blank" rel="noopener noreferrer">{t}<ExternalLink class="size-3" aria-hidden="true" /><span class="sr-only"> (opens attack.mitre.org)</span></a>
									{/each}
								</dd>
							{/if}
						</dl>
						{#if d.rule_id}<p class="mt-3 text-xs"><a class="link" href="/security?tab=rules&q={encodeURIComponent(d.rule_id)}">See this rule’s hits and mode</a></p>{/if}
					</section>
				{/if}
			</div>
		</div>

		{#if responding}
			<RespondDialog
				agentId={d.agent_id}
				hostname={d.hostname}
				kind={responding.kind}
				pid={responding.pid}
				path={responding.path}
				processName={responding.processName}
				detectionId={d.id}
				onclose={() => (responding = null)}
				ondone={() => res.reload()}
			/>
		{/if}
		{#if restoring && d.quarantine_id}
			<RestoreDialog agentId={d.agent_id} hostname={d.hostname} id={d.quarantine_id} path={path ?? 'the quarantined file'} detectionId={d.id} onclose={() => (restoring = false)} ondone={() => res.reload()} />
		{/if}
	{/snippet}
</Async>
