<script lang="ts">
	import { KeyRound, RotateCcw } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { vaultAccess } from '#lib/docs/vault.js';
	import { localAdminLabel, localAdminTone, type LocalAdminView } from '#lib/devicesec.js';
	import { ago, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed, can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import CredentialPopup from './CredentialPopup.svelte';

	/** The managed local admin account: shown when the policy is on or it was ever rotated. */
	let { agentId, online, hostname }: { agentId: string; online: boolean; hostname: string } = $props();
	const v = resource(() => api.get<LocalAdminView>(`/agents/${agentId}/local-admin`));
	liveReload(() => v.reload(), (e) => e.type === 'security' && e.agent_id === agentId, { debounceMs: 1000 });
	let showing = $state(false);
	async function rotate() {
		await attempt(() => api.post(`/agents/${agentId}/local-admin/rotate`), 'Rotation started.');
		v.reload();
	}
	const reasons: Record<string, string> = { first: 'first rotation', schedule: 'on schedule', reveal: 'after a reveal', manual: 'by hand' };
</script>

{#if v.data && (v.data.policy.enabled || v.data.state)}
	{@const s = v.data.state}
	<section class="card" aria-label="Local admin">
		<header class="border-border flex min-h-12 items-center justify-between gap-3 border-b px-4 py-3">
			<h2 class="panel-title">Local admin</h2>
			{#if s}<Badge tone={localAdminTone[s.status]}>{localAdminLabel[s.status]}</Badge>{/if}
		</header>
		<dl class="dl px-4 py-3 text-sm">
			<dt>Account</dt><dd class="font-mono text-[13px]">{s?.account ?? v.data.policy.account}</dd>
			<dt>Last rotated</dt><dd title={datetime(s?.rotated_at)}>{s?.rotated_at ? `${ago(s.rotated_at)}${s.rotate_reason ? `, ${reasons[s.rotate_reason]}` : ''}` : 'Never'}</dd>
			{#if v.data.policy.enabled}<dt>Next</dt><dd title={datetime(s?.next_rotate_at)}>{s?.next_rotate_at ? datetime(s.next_rotate_at) : 'When the device is online'}</dd>{/if}
		</dl>
		{#if !v.data.policy.enabled}<p class="text-muted px-4 pb-3 text-xs">Rotation is off in this device's policy. The account and its last password are left as they are.</p>{/if}
		{#if v.data.needs_data_key}<p class="text-warning px-4 pb-3 text-xs">The server has no RMM_DATA_KEY, so passwords aren't rotated.</p>{/if}
		{#if s?.last_error && s.status !== 'ok'}<p class="text-danger px-4 pb-3 text-xs break-words">{s.last_error}</p>{/if}
		{#if s?.status === 'failed' || s?.status === 'pending'}<p class="text-muted px-4 pb-3 text-xs">The password on the device is the previous one, in the credential's history.</p>{/if}
		<div class="border-border flex flex-wrap gap-2 border-t px-4 py-3">
			{#if s?.vault_item_id && vaultAccess() !== 'none'}<Button size="sm" icon={KeyRound} onclick={() => (showing = true)}>Show password</Button>{/if}
			{#if can('technician') && allowed('vault.manage') && v.data.policy.enabled}<Button size="sm" variant="ghost" icon={RotateCcw} disabled={!online} onclick={rotate}>Rotate now</Button>{/if}
		</div>
	</section>
	{#if showing && s?.vault_item_id}
		<CredentialPopup itemId={s.vault_item_id} title="Local admin: {hostname}" onclose={() => (showing = false)} />
	{/if}
{/if}
