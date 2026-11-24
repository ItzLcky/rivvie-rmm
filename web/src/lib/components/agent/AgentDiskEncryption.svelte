<script lang="ts">
	import { KeyRound, RefreshCw, RotateCcw } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { vaultAccess } from '#lib/docs/vault.js';
	import { kindLabel, protectorLabel, volumeStatusLabel, volumeStatusTone, type AgentDiskEncryption, type DiskVolume } from '#lib/devicesec.js';
	import { ago, datetime } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed, can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import CredentialPopup from './CredentialPopup.svelte';

	/** The device's volumes and their encryption, the TPM, and the escrowed recovery keys. */
	let { agentId, online, hostname }: { agentId: string; online: boolean; hostname: string } = $props();
	const d = resource(() => api.get<AgentDiskEncryption>(`/agents/${agentId}/disk-encryption`));
	liveReload(() => d.reload(), (e) => e.type === 'security' && e.agent_id === agentId, { debounceMs: 1000 });
	let showing = $state<DiskVolume | null>(null);

	async function refresh() {
		await attempt(() => api.post(`/agents/${agentId}/disk-encryption/refresh`), 'Asked the device to report its disk encryption.');
	}
	async function rotate(v: DiskVolume) {
		const ok = await confirmAction({
			title: `Rotate the recovery password of ${v.volume_id}?`,
			message: 'BitLocker makes a new recovery password and removes the old one; the new one is escrowed when the device reports. The old one stays in the credential\'s history.',
			confirmLabel: 'Rotate'
		});
		if (ok && (await attempt(() => api.post<{ message: string }>(`/agents/${agentId}/disk-encryption/${encodeURIComponent(v.volume_id)}/rotate-key`), 'Recovery password rotated.'))) d.reload();
	}
	const tpm = $derived(d.data?.tpm);
</script>

<section class="card overflow-x-auto" aria-label="Disk encryption">
	<header class="border-border flex min-h-12 flex-wrap items-center gap-3 border-b px-4 py-3">
		<h2 class="panel-title">Disk encryption</h2>
		{#if d.data?.reported_at}<span class="text-muted text-xs" title={datetime(d.data.reported_at)}>Reported {ago(d.data.reported_at)}</span>{/if}
		{#if tpm}<Badge tone={tpm.present ? 'neutral' : 'warning'}>{tpm.present ? `TPM ${tpm.version ?? ''}`.trim() : 'No TPM'}{tpm.present && tpm.ready === false ? ' (not ready)' : ''}</Badge>{/if}
		{#if can('technician')}<Button size="sm" icon={RefreshCw} class="ml-auto" disabled={!online} onclick={refresh}>Check now</Button>{/if}
	</header>
	{#if d.loading && !d.data}
		<div class="p-4"><Skeleton lines={3} /></div>
	{:else if !d.data?.reported_at}
		<EmptyState compact title="Not reported yet" description="Agents from this release report BitLocker, FileVault or LUKS state when they connect." />
	{:else}
		{#if d.data.error}<p class="text-warning border-border border-b px-4 py-2 text-xs">{d.data.error}</p>{/if}
		<table class="table">
			<thead><tr><th>Volume</th><th>Status</th><th>Protectors</th><th>Recovery key</th></tr></thead>
			<tbody>
				{#each d.data.volumes as v (v.volume_id)}
					<tr>
						<td>
							<div class="font-mono text-xs">{v.volume_id}</div>
							<div class="text-muted text-xs">{v.role === 'os' ? 'System' : 'Data'} · {kindLabel[v.kind]}{v.method ? ` · ${v.method}` : ''}</div>
						</td>
						<td>
							<Badge tone={volumeStatusTone[v.status]}>{volumeStatusLabel[v.status]}{v.status === 'encrypting' || v.status === 'decrypting' ? ` ${Math.round(v.percent ?? 0)}%` : ''}</Badge>
							{#if v.status === 'suspended' && v.suspended_since}<div class="text-muted mt-0.5 text-xs">since {ago(v.suspended_since)}</div>{/if}
						</td>
						<td class="text-xs">{v.protectors.map((p) => protectorLabel[p] ?? p).join(', ') || '–'}</td>
						<td class="text-xs">
							{#if v.kind !== 'bitlocker'}
								<span class="text-muted">–</span>
							{:else if v.escrowed}
								<div class="flex flex-wrap items-center gap-2">
									<Badge tone="success">Escrowed</Badge>
									{#if v.vault_item_id && vaultAccess() !== 'none'}<Button size="sm" icon={KeyRound} onclick={() => (showing = v)}>Recovery key</Button>{/if}
									{#if can('technician') && allowed('security.respond')}<Button size="sm" variant="ghost" icon={RotateCcw} disabled={!online} onclick={() => rotate(v)}>Rotate</Button>{/if}
								</div>
							{:else}
								<Badge tone="warning">{v.recovery_protector_id ? 'Not escrowed' : 'No recovery password'}</Badge>
								{#if v.escrow_error}<div class="text-muted mt-0.5 max-w-64 text-xs break-words">{v.escrow_error}</div>{:else if !d.data.escrow_recovery_keys}<div class="text-muted mt-0.5 text-xs">Escrow is off in this device's policy.</div>{/if}
							{/if}
						</td>
					</tr>
				{:else}
					<tr><td colspan="4" class="text-muted py-6 text-center">No fixed volumes reported.</td></tr>
				{/each}
			</tbody>
		</table>
	{/if}
</section>

{#if showing?.vault_item_id}
	<CredentialPopup itemId={showing.vault_item_id} title="Recovery key: {hostname} {showing.volume_id}" onclose={() => (showing = null)} />
{/if}
