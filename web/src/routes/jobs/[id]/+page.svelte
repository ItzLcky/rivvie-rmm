<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';
	import type { JobDetail } from '#lib/types.js';
	import JobBadge from '#lib/components/JobBadge.svelte';

	let job = $state<JobDetail | null>(null);
	const id = $derived(page.params.id!);

	$effect(() => {
		let t: ReturnType<typeof setTimeout>;
		const load = async () => {
			job = await api.get<JobDetail>(`/jobs/${id}`);
			// Poll while it's still pending/running.
			if (job.status === 'queued' || job.status === 'sent') t = setTimeout(load, 1000);
		};
		load();
		return () => clearTimeout(t);
	});
</script>

{#if job}
	<div class="mb-1 text-sm text-slate-500"><a href="/jobs" class="hover:text-slate-300">Jobs</a> / {job.id.slice(0, 8)}</div>
	<div class="mb-4 flex items-center gap-3">
		<h1 class="text-xl font-semibold">{job.script_name ?? `Ad-hoc ${job.interpreter} script`}</h1>
		<JobBadge status={job.status} />
	</div>
	<div class="card mb-4 grid grid-cols-2 gap-4 p-4 text-sm md:grid-cols-5">
		<div><div class="label">Agent</div><a class="text-sky-400 hover:underline" href="/agents/{job.agent_id}">{job.hostname}</a></div>
		<div><div class="label">Exit code</div><span class="tabular-nums">{job.exit_code ?? '–'}</span></div>
		<div><div class="label">Duration</div>{job.duration_ms != null ? `${(job.duration_ms / 1000).toFixed(2)}s` : '–'}</div>
		<div><div class="label">Created</div>{datetime(job.created_at)}</div>
		<div><div class="label">By</div>{job.created_by_name ?? '–'}</div>
	</div>
	<div class="label">Output</div>
	<pre class="card mb-4 max-h-[50vh] min-h-24 overflow-auto p-3 font-mono text-xs whitespace-pre-wrap">{job.stdout}{#if job.stderr}<span class="text-red-400">{job.stderr}</span>{/if}{#if !job.stdout && !job.stderr}<span class="text-slate-500">{job.status === 'queued' ? 'Waiting for the agent to come online…' : job.status === 'sent' ? 'Running…' : 'No output.'}</span>{/if}</pre>
	<details>
		<summary class="cursor-pointer text-sm text-slate-400">Script ({job.interpreter}, timeout {job.timeout_secs}s)</summary>
		<pre class="card mt-2 overflow-auto p-3 font-mono text-xs">{job.body}</pre>
	</details>
{/if}
