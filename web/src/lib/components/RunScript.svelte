<script lang="ts">
	import { goto } from '$app/navigation';
	import { api } from '#lib/api.js';
	import { interpreterLabel, interpreters, plural } from '#lib/format.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, Interpreter, Script } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import CodeEditor from './CodeEditor.svelte';
	import ParamInputs, { missing } from './scripts/ParamInputs.svelte';

	let {
		agents,
		onclose,
		initial,
		ticketId
	}: {
		agents: Pick<AgentSummary, 'id' | 'hostname' | 'os_family' | 'client_id'>[];
		onclose: () => void;
		/** Prefill (e.g. from a script page's "Run"). */
		initial?: { scriptId?: string };
		/** Run from this ticket: the result goes on its timeline, and we stay on the ticket. */
		ticketId?: string;
	} = $props();

	const windowsOnly = $derived(agents.every((a) => a.os_family === 'windows'));
	const ADHOC = '__adhoc';
	let scripts = $state<Script[]>([]);
	let scriptId = $state(ADHOC);
	$effect.pre(() => {
		if (initial?.scriptId) scriptId = initial.scriptId;
	});
	let interpreter = $state<Interpreter>('bash');
	let body = $state('');
	let args = $state('');
	let timeout = $state(300);
	let busy = $state(false);
	let values = $state<Record<string, string>>({});
	// The vault of the devices' one client can fill secrets.
	const oneClient = $derived(agents.length && agents.every((a) => a.client_id === agents[0].client_id) ? agents[0].client_id : null);

	$effect(() => {
		interpreter = windowsOnly ? 'powershell' : 'bash';
		// A client's own script only runs on that client's agents.
		api.get<Script[]>('/scripts').then((s) => (scripts = s.filter((x) => !x.client_id || agents.every((a) => a.client_id === x.client_id))));
	});

	const selected = $derived(scripts.find((s) => s.id === scriptId));
	const items = $derived([
		{ value: ADHOC, label: 'Ad-hoc script', hint: 'type it below' },
		...scripts.map((s) => ({ value: s.id, label: s.name, hint: `${interpreterLabel(s.interpreter)}${s.client_name ? ` · ${s.client_name}` : ''}` }))
	]);
	const specs = $derived(selected?.params ?? []);
	const lacking = $derived(missing(specs, values));
	const params = $derived(Object.fromEntries(Object.entries(values).filter(([k, v]) => v !== '' && specs.some((s) => s.name === k))));
	const argList = $derived(args.split('\n').map((a) => a.trim()).filter(Boolean));

	async function run(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const ids = agents.map((a) => a.id);
			const payload = {
				...(selected ? { agent_ids: ids, script_id: selected.id, args: argList, params } : { agent_ids: ids, interpreter, body, args: argList, timeout_secs: timeout }),
				ticket_id: ticketId ?? null
			};
			const res = await api.post<{ jobs: { job_id: string; status: string }[]; skipped: string[] }>('/jobs', payload);
			onclose();
			if (ticketId) {
				toast.success('Started. The result will be added to the ticket.');
				return;
			}
			const queued = res.jobs.filter((j) => j.status === 'queued').length;
			toast.success(
				`Started on ${plural(res.jobs.length, 'agent')}${queued ? ` (${queued} offline, queued)` : ''}${res.skipped.length ? `; ${res.skipped.length} skipped` : ''}.`
			);
			await goto(res.jobs.length === 1 ? `/jobs/${res.jobs[0].job_id}` : '/jobs');
		} catch (e) {
			toast.error(e);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Run script" description="On {agents.length === 1 ? agents[0].hostname : plural(agents.length, 'agent')}. Offline agents queue the job and run it when they reconnect." {onclose} size="lg">
	<form id="run-script" class="space-y-4" onsubmit={run}>
		<Field label="Script" id="rs-script">
			<Combobox id="rs-script" bind:value={scriptId} {items} placeholder="Pick a saved script…" />
		</Field>
		{#if selected}
			<div>
				<div class="label">{interpreterLabel(selected.interpreter)} · timeout {selected.timeout_secs}s</div>
				<pre class="code-block max-h-64">{selected.body}</pre>
			</div>
			{#if specs.length}
				<fieldset class="space-y-3">
					<legend class="text-sm font-semibold">Parameters</legend>
					<ParamInputs {specs} bind:values clientId={oneClient} variables idPrefix="rs-p" />
				</fieldset>
			{/if}
		{:else}
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Interpreter" id="rs-interp">
					<Select id="rs-interp" bind:value={interpreter} options={interpreters.map((i) => ({ value: i.value, label: i.label }))} />
				</Field>
				<Field label="Timeout (seconds)" id="rs-timeout">
					<Input id="rs-timeout" type="number" min="1" max="86400" bind:value={timeout} />
				</Field>
			</div>
			<Field label="Script body" id="rs-body">
				<CodeEditor id="rs-body" bind:value={body} {interpreter} minHeight="12rem" />
			</Field>
		{/if}
		<Field label="Arguments" id="rs-args" hint="One per line, passed in order: $1… in sh/bash, $args in PowerShell, %1… in cmd, sys.argv in Python.">
			<Textarea id="rs-args" rows={2} class="font-mono text-xs" spellcheck="false" bind:value={args} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="run-script" loading={busy} disabled={(!selected && !body.trim()) || lacking.length > 0}>Run</Button>
	{/snippet}
</Modal>
