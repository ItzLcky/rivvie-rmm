<script lang="ts" module>
	export type RespondKind = 'kill_process' | 'quarantine_file' | 'scan_path' | 'isolate' | 'release' | 'collect_triage';
</script>

<script lang="ts">
	import { api } from '#lib/api.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { ResponseAction } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/**
	 * Confirms one response action (with its inputs) and sends it to the agent. The result
	 * arrives later, in the agent's action history.
	 */
	let {
		agentId,
		hostname,
		kind,
		pid: initialPid,
		path: initialPath = '',
		processName,
		detectionId,
		onclose,
		ondone
	}: {
		agentId: string;
		hostname: string;
		kind: RespondKind;
		pid?: number;
		path?: string;
		/** Shown in the kill dialog. */
		processName?: string;
		/** The detection this answers, so the action shows on its page. */
		detectionId?: string;
		onclose: () => void;
		ondone?: () => void;
	} = $props();

	// svelte-ignore state_referenced_locally
	let pid = $state(initialPid != null ? String(initialPid) : '');
	// svelte-ignore state_referenced_locally
	let path = $state(initialPath);
	let tree = $state(true);
	let allow = $state('');
	let busy = $state(false);
	let error = $state('');

	const copy: Record<RespondKind, { title: string; button: string; danger?: boolean; done: string }> = $derived({
		kill_process: { title: `Kill a process on ${hostname}`, button: 'Kill process', danger: true, done: 'Kill sent.' },
		quarantine_file: { title: `Quarantine a file on ${hostname}`, button: 'Quarantine file', danger: true, done: 'Quarantine sent.' },
		scan_path: { title: `Scan a path on ${hostname}`, button: 'Start scan', done: 'Scan started.' },
		isolate: { title: `Isolate ${hostname} from the network?`, button: 'Isolate network', danger: true, done: 'Isolation sent.' },
		release: { title: `Release ${hostname} from isolation?`, button: 'Release', done: 'Release sent.' },
		collect_triage: { title: `Collect a triage package from ${hostname}?`, button: 'Collect package', done: 'Collection started.' }
	});
	const c = $derived(copy[kind]);

	function action(): ResponseAction | string {
		switch (kind) {
			case 'kill_process': {
				const n = Number(pid);
				if (!Number.isInteger(n) || n <= 0) return 'A process ID is a whole number';
				if (n <= 4) return 'That’s a system process';
				return { type: 'kill_process', pid: n, tree };
			}
			case 'quarantine_file':
			case 'scan_path':
				return path.trim() ? { type: kind, path: path.trim() } : 'A path is required';
			case 'isolate': {
				const hosts = allow.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);
				return hosts.length > 20 ? 'Up to 20 extra hosts' : { type: 'isolate', allow: hosts };
			}
			case 'release':
				return { type: 'release' };
			case 'collect_triage':
				return { type: 'collect_triage' };
		}
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		const a = action();
		if (typeof a === 'string') {
			error = a;
			return;
		}
		error = '';
		busy = true;
		try {
			await api.post(`/agents/${agentId}/security/respond`, { action: a, detection_id: detectionId ?? null });
			toast.success(`${c.done} The result shows in the action history when ${hostname} answers.`);
			ondone?.();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title={c.title} {onclose} size="md">
	<form id="respond-form" class="space-y-4" onsubmit={submit}>
		{#if kind === 'kill_process'}
			<p class="text-muted text-sm">The agent ends the process immediately, without asking it to close. Unsaved work in it is lost.</p>
			<Field label="Process ID" id="r-pid" required error={error}>
				<Input id="r-pid" inputmode="numeric" class="w-32" bind:value={pid} invalid={!!error} />
			</Field>
			{#if processName}<p class="text-muted -mt-2 font-mono text-xs break-all">{processName}</p>{/if}
			<Checkbox bind:checked={tree}>Also kill everything it started (the process tree)</Checkbox>
		{:else if kind === 'quarantine_file' || kind === 'scan_path'}
			<p class="text-muted text-sm">
				{kind === 'quarantine_file'
					? 'The file is moved into the agent’s protected quarantine store, scrambled so it can’t run. You can restore it later.'
					: 'Our sensor scans this file, or every file in this folder, with its current content. Findings show up as detections.'}
			</p>
			<Field label={kind === 'quarantine_file' ? 'File' : 'File or folder'} id="r-path" required error={error}>
				<Input id="r-path" class="font-mono" spellcheck={false} bind:value={path} invalid={!!error} placeholder={kind === 'scan_path' ? 'C:\\Users\\jsmith\\Downloads' : ''} />
			</Field>
		{:else if kind === 'isolate'}
			<p class="text-sm">The agent blocks all network traffic except to this RMM server, DNS and DHCP. You keep control of the machine (scripts, terminal, remote desktop); everything else on it loses the network until you release it.</p>
			<p class="text-muted text-sm">Isolation survives a restart. Release it from the Security tab.</p>
			<Field label="Also allow (optional)" id="r-allow" hint="Hostnames or IP addresses, separated by spaces or commas, e.g. your backup server. Up to 20." error={error}>
				<Textarea id="r-allow" rows={2} class="font-mono" spellcheck={false} bind:value={allow} />
			</Field>
		{:else if kind === 'release'}
			<p class="text-muted text-sm">The agent removes its firewall rules and the machine gets its normal network back.</p>
		{:else}
			<p class="text-muted text-sm">The agent gathers running processes, network connections, autoruns, its recent telemetry and logs into one archive and uploads it here. It can take a few minutes; a Download link appears in the action history.</p>
		{/if}
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant={c.danger ? 'danger' : 'primary'} type="submit" form="respond-form" loading={busy}>{c.button}</Button>
	{/snippet}
</Modal>
