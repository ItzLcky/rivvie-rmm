<script lang="ts">
	import { page } from '$app/state';
	import { ArrowDownToLine, RotateCcw } from '@lucide/svelte';
	import { tick } from 'svelte';
	import { api } from '#lib/api.js';
	import { datetime, interpreterLabel, ms } from '#lib/format.js';
	import { rerun } from '#lib/jobs.js';
	import { live, onLive } from '#lib/live.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { JobDetail } from '#lib/types.js';
	import { qs } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import CopyButton from '#lib/ui/CopyButton.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';

	const id = $derived(page.params.id!);
	let job = $state<JobDetail | null>(null);
	let error = $state<Error | null>(null);
	let out: HTMLPreElement | undefined = $state();
	let follow = $state(true);

	const running = $derived(job?.status === 'queued' || job?.status === 'sent');

	// The first load gets everything; later ones only what's new since (by length), so a chatty
	// script doesn't re-download its whole output on every update.
	let inflight = false;
	let again = false;
	async function load(full = false) {
		if (inflight) {
			again = true;
			return;
		}
		inflight = true;
		try {
			const prev = full ? null : job;
			const j = await api.get<JobDetail>(`/jobs/${id}${qs({ since_stdout: prev?.stdout_len, since_stderr: prev?.stderr_len })}`);
			if (prev && prev.id === j.id && j.stdout_len >= prev.stdout_len && j.stderr_len >= prev.stderr_len) {
				j.stdout = prev.stdout + j.stdout;
				j.stderr = prev.stderr + j.stderr;
			} else if (prev) {
				// Output was replaced (the agent resent it after a reconnect): start over.
				inflight = false;
				return load(true);
			}
			job = j;
			error = null;
			if (follow) {
				await tick();
				out?.scrollTo({ top: out.scrollHeight });
			}
		} catch (e) {
			error = e as Error;
		} finally {
			inflight = false;
			if (again) {
				again = false;
				load();
			}
		}
	}

	$effect(() => {
		void id;
		job = null;
		load(true);
	});

	// Live: output and status events for this job. Without the stream, poll while it runs.
	let pending: ReturnType<typeof setTimeout> | undefined;
	onLive((e) => {
		if ((e.type === 'job' && e.id === id) || e.type === 'resync' || e.type === 'jobs') {
			clearTimeout(pending);
			pending = setTimeout(() => load(), 150);
		}
	});
	$effect(() => {
		if (!running || live.status === 'live') return;
		const t = setInterval(() => load(), 1500);
		return () => clearInterval(t);
	});

	function onscroll() {
		if (!out) return;
		follow = out.scrollTop + out.clientHeight >= out.scrollHeight - 24;
	}
</script>

<svelte:head>{#if job}<title>{job.script_name ?? 'Ad-hoc script'} on {job.hostname}</title>{/if}</svelte:head>

{#if error && !job}
	<div class="card"><ErrorState {error} onretry={() => load(true)} /></div>
{:else if !job}
	<div class="mb-4 space-y-2"><Skeleton class="h-3 w-32" /><Skeleton class="h-7 w-72" /></div>
	<div class="card mb-4 p-4"><Skeleton lines={2} /></div>
	<Skeleton class="h-64 w-full" />
{:else}
	<PageHeader
		title={job.script_name ?? `Ad-hoc ${interpreterLabel(job.interpreter)} script`}
		crumbs={[{ label: 'Jobs', href: '/jobs' }, { label: job.hostname, href: `/agents/${job.agent_id}` }, { label: job.id.slice(0, 8) }]}
	>
		{#snippet meta()}<JobBadge status={job!.status} />{/snippet}
		{#snippet actions()}
			{#if can('technician') && !running}<Button icon={RotateCcw} onclick={() => rerun(job!.id)}>Run again</Button>{/if}
		{/snippet}
	</PageHeader>

	<dl class="card mb-4 grid grid-cols-2 gap-x-4 gap-y-3 p-4 text-sm sm:grid-cols-3 lg:grid-cols-6">
		<div><dt class="text-muted text-xs">Agent</dt><dd><a class="link" href="/agents/{job.agent_id}">{job.hostname}</a></dd></div>
		<div><dt class="text-muted text-xs">Exit code</dt><dd class="tabular">{job.exit_code ?? '–'}</dd></div>
		<div><dt class="text-muted text-xs">Duration</dt><dd>{ms(job.duration_ms)}</dd></div>
		<div><dt class="text-muted text-xs">Created</dt><dd>{datetime(job.created_at)}</dd></div>
		<div><dt class="text-muted text-xs">Finished</dt><dd>{datetime(job.finished_at)}</dd></div>
		<div><dt class="text-muted text-xs">By</dt><dd>{#if job.schedule_id}<a class="link" href="/schedules/{job.schedule_id}">{job.schedule_name}</a>{#if job.created_by_name}<span class="text-muted"> · {job.created_by_name}</span>{/if}{:else}{job.created_by_name ?? '–'}{/if}</dd></div>
	</dl>

	<section class="card mb-4 overflow-hidden" aria-label="Output">
		<header class="border-border flex items-center gap-2 border-b px-3 py-1.5">
			<h2 class="panel-title">Output</h2>
			{#if running}<span class="text-info text-xs">{job.status === 'queued' ? 'waiting for the agent' : live.status === 'live' ? 'streaming' : 'refreshing'}</span>{/if}
			<div class="ml-auto flex items-center gap-1">
				{#if !follow && running}<Button size="xs" variant="ghost" icon={ArrowDownToLine} onclick={() => ((follow = true), out?.scrollTo({ top: out.scrollHeight }))}>Follow</Button>{/if}
				<CopyButton text={job.stdout + job.stderr} label="Copy output" />
			</div>
		</header>
		<pre
			bind:this={out}
			{onscroll}
			class="max-h-[60vh] min-h-32 overflow-auto p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words"
			style="background: var(--terminal-bg); color: var(--terminal-fg)"
			aria-live={running ? 'polite' : undefined}>{job.stdout}{#if job.stderr}<span class="text-[#ff8a80]">{job.stderr}</span>{/if}{#if !job.stdout && !job.stderr}<span class="opacity-60">{job.status === 'queued' ? 'Waiting for the agent to come online…' : job.status === 'sent' ? 'Running…' : 'No output.'}</span>{/if}</pre>
		{#if job.stderr}<p class="text-muted border-border border-t px-3 py-1.5 text-xs">Standard error is shown in red, after standard output.</p>{/if}
	</section>

	<details class="card group">
		<summary class="text-muted hover:text-fg cursor-pointer px-4 py-2.5 text-sm select-none">
			Script · {interpreterLabel(job.interpreter)} · timeout {job.timeout_secs}s{job.args.length ? ` · ${job.args.length} argument${job.args.length === 1 ? '' : 's'}` : ''}
		</summary>
		<div class="border-border space-y-2 border-t p-4">
			{#if job.args.length}<p class="text-sm">Arguments: {#each job.args as a, i (i)}<code class="bg-sunken mr-1 rounded px-1 text-xs">{a}</code>{/each}</p>{/if}
			<pre class="code-block max-h-96">{job.body}</pre>
		</div>
	</details>
{/if}
