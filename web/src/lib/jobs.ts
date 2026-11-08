import { goto } from '$app/navigation';
import { api } from './api';
import { toast } from './toast.svelte';
import type { JobDetail } from './types';

/**
 * Runs a finished job again on the same agent: the same saved script (its current version) or
 * the same ad-hoc body, with the same arguments and timeout. Opens the new job.
 */
export async function rerun(jobId: string, opts: { open?: boolean } = { open: true }) {
	try {
		const j = await api.get<JobDetail>(`/jobs/${jobId}?since_stdout=100000000&since_stderr=100000000`);
		const payload = j.script_id
			? { agent_ids: [j.agent_id], script_id: j.script_id, args: j.args }
			: { agent_ids: [j.agent_id], interpreter: j.interpreter, body: j.body, args: j.args, timeout_secs: j.timeout_secs };
		const r = await api.post<{ jobs: { job_id: string; status: string }[] }>('/jobs', payload);
		const next = r.jobs[0];
		toast.success(next.status === 'queued' ? `Queued on ${j.hostname}: it runs when the agent reconnects.` : `Running again on ${j.hostname}.`, {
			href: opts.open ? undefined : { label: 'Open job', href: `/jobs/${next.job_id}` }
		});
		if (opts.open) await goto(`/jobs/${next.job_id}`);
		return next.job_id;
	} catch (e) {
		toast.error(e);
	}
}
