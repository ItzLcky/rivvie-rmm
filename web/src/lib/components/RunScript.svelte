<script lang="ts">
	import { goto } from '$app/navigation';
	import { api } from '#lib/api.js';
	import { interpreters } from '#lib/format.js';
	import type { AgentSummary, Interpreter, Script } from '#lib/types.js';
	import Modal from './Modal.svelte';

	let { agents, onclose }: { agents: Pick<AgentSummary, 'id' | 'hostname' | 'os_family'>[]; onclose: () => void } = $props();

	const windowsOnly = $derived(agents.every((a) => a.os_family === 'windows'));
	let scripts = $state<Script[]>([]);
	let scriptId = $state('');
	let interpreter = $state<Interpreter>('bash');
	let body = $state('');
	let timeout = $state(300);
	let busy = $state(false);
	let error = $state('');

	$effect(() => {
		interpreter = windowsOnly ? 'powershell' : 'bash';
		api.get<Script[]>('/scripts').then((s) => (scripts = s));
	});

	const selected = $derived(scripts.find((s) => s.id === scriptId));

	async function run() {
		busy = true;
		error = '';
		try {
			const payload = selected
				? { agent_ids: agents.map((a) => a.id), script_id: selected.id }
				: { agent_ids: agents.map((a) => a.id), interpreter, body, timeout_secs: timeout };
			const res = await api.post<{ jobs: { job_id: string }[] }>('/jobs', payload);
			onclose();
			await goto(res.jobs.length === 1 ? `/jobs/${res.jobs[0].job_id}` : '/jobs');
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Run script on {agents.length === 1 ? agents[0].hostname : `${agents.length} agents`}" {onclose} wide>
	<div class="space-y-3">
		<div>
			<label class="label" for="script">Saved script</label>
			<select id="script" class="input" bind:value={scriptId}>
				<option value="">Ad-hoc script…</option>
				{#each scripts as s (s.id)}<option value={s.id}>{s.name} ({s.interpreter})</option>{/each}
			</select>
		</div>
		{#if selected}
			<pre class="max-h-64 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-slate-300">{selected.body}</pre>
		{:else}
			<div class="grid grid-cols-2 gap-3">
				<div>
					<label class="label" for="interp">Interpreter</label>
					<select id="interp" class="input" bind:value={interpreter}>
						{#each interpreters as i (i.value)}<option value={i.value}>{i.label}</option>{/each}
					</select>
				</div>
				<div>
					<label class="label" for="timeout">Timeout (seconds)</label>
					<input id="timeout" class="input" type="number" min="1" bind:value={timeout} />
				</div>
			</div>
			<div>
				<label class="label" for="body">Script</label>
				<textarea id="body" class="input h-48 font-mono text-xs" spellcheck="false" bind:value={body}
					placeholder={interpreter === 'powershell' ? 'Get-Service | Where-Object Status -eq Running' : 'uptime && df -h'}></textarea>
			</div>
		{/if}
		{#if error}<p class="text-sm text-red-400">{error}</p>{/if}
		<div class="flex justify-end gap-2">
			<button class="btn-ghost" onclick={onclose}>Cancel</button>
			<button class="btn-primary" disabled={busy || (!selected && !body.trim())} onclick={run}>{busy ? 'Starting…' : 'Run'}</button>
		</div>
		<p class="text-xs text-slate-500">Offline agents queue the job and run it when they reconnect.</p>
	</div>
</Modal>
