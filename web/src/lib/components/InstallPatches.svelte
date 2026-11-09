<script lang="ts">
	import { Download } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { plural } from '#lib/format.js';
	import { rebootPolicies } from '#lib/patches.js';
	import { toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	/**
	 * Confirms and starts an install now, outside any maintenance window. `updateIds` null:
	 * every approved update each agent still needs.
	 */
	let {
		agentIds,
		updateIds = null,
		summary,
		allOrNothing = false,
		onclose,
		ondone
	}: {
		agentIds: string[];
		updateIds?: string[] | null;
		/** What's being installed, e.g. "3 updates on web-01". */
		summary: string;
		/** pacman: everything outstanding is upgraded, whatever was picked. */
		allOrNothing?: boolean;
		onclose: () => void;
		ondone?: () => void;
	} = $props();

	let reboot = $state('');
	let busy = $state(false);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const r = await api.post<{ runs: { sent: boolean }[]; skipped: { hostname: string; reason: string }[] }>('/patches/install', {
				agent_ids: agentIds,
				update_ids: updateIds,
				reboot_policy: reboot || null
			});
			const queued = r.runs.filter((x) => !x.sent).length;
			let msg = `Install started on ${plural(r.runs.length, 'agent')}.`;
			if (queued) msg += ` ${queued} offline: it starts when they reconnect.`;
			if (r.skipped.length) msg += ` Skipped ${r.skipped.length}: ${r.skipped[0].hostname} ${r.skipped[0].reason}${r.skipped.length > 1 ? ', …' : ''}.`;
			toast.success(msg);
			ondone?.();
			onclose();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Install updates now?" {onclose} size="sm">
	<form id="install-patches" class="space-y-4" onsubmit={submit}>
		<p class="text-sm">{summary}. This starts right away, ignoring maintenance windows and deferrals.{#if updateIds} The updates are marked approved.{/if}</p>
		{#if allOrNothing}
			<p class="border-warning/40 bg-warning-soft text-warning rounded-md border px-3 py-2 text-xs">Arch Linux can't install single updates: <code>pacman -Syu</code> upgrades every outstanding package.</p>
		{/if}
		<Field label="Restart" id="install-reboot" hint={rebootPolicies.find((r) => r.value === reboot)?.hint ?? 'What the agent’s patch policy says'}>
			<Select id="install-reboot" class="w-full" bind:value={reboot} options={[{ value: '', label: 'As the policy says' }, ...rebootPolicies.map((r) => ({ value: r.value, label: r.label }))]} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="install-patches" icon={Download} loading={busy}>Install</Button>
	{/snippet}
</Modal>
