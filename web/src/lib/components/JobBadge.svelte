<script lang="ts">
	import type { JobStatus } from '#lib/types.js';
	let { status }: { status: JobStatus } = $props();
	const styles: Record<JobStatus, string> = {
		queued: 'bg-slate-800 text-slate-300',
		sent: 'bg-sky-950 text-sky-300',
		succeeded: 'bg-emerald-950 text-emerald-300',
		failed: 'bg-red-950 text-red-300',
		timed_out: 'bg-amber-950 text-amber-300',
		error: 'bg-red-950 text-red-300',
		cancelled: 'bg-slate-800 text-slate-400'
	};
	const labels: Partial<Record<JobStatus, string>> = { sent: 'running', timed_out: 'timed out' };
</script>

<span class="rounded px-1.5 py-0.5 text-xs font-medium {styles[status]}">{labels[status] ?? status}</span>
