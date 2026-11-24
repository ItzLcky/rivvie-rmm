<script lang="ts">
	import { api } from '#lib/api.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Remediation } from '#lib/vulns.js';
	import Button from '#lib/ui/Button.svelte';

	/**
	 * How to fix a finding from here: install the device's pending update for the package
	 * (Linux), upgrade it with its catalog package (Windows), or add the product to the catalog.
	 */
	let { agentId, remediation, fixed, ondone }: { agentId: string; remediation: Remediation; fixed: string | null; ondone?: () => void } = $props();

	async function install(updateId: string) {
		if (await attempt(() => api.post('/patches/install', { agent_ids: [agentId], update_ids: [updateId] }), 'Update sent to the device.')) ondone?.();
	}
	async function upgrade(packageId: string) {
		if (await attempt(() => api.post('/software/deploy', { package_id: packageId, op: 'upgrade', agent_ids: [agentId] }), 'Upgrade started.')) ondone?.();
	}
</script>

{#if remediation?.kind === 'patch'}
	{#if can('technician')}
		<Button size="xs" onclick={() => install(remediation.update_id)} title="Approve and install {remediation.title}{remediation.version ? ` ${remediation.version}` : ''}">
			{remediation.approval === 'approved' ? 'Install update' : 'Approve & install'}
		</Button>
	{:else}
		<span class="text-muted text-xs">Update pending</span>
	{/if}
{:else if remediation?.kind === 'upgrade'}
	{#if can('technician')}
		<Button size="xs" onclick={() => upgrade(remediation.package_id)}>Upgrade with {remediation.package_name}</Button>
	{:else}
		<span class="text-muted text-xs">Catalog: {remediation.package_name}</span>
	{/if}
{:else if remediation?.kind === 'catalog'}
	<a class="link text-xs whitespace-nowrap" href="/software">Add {remediation.product_name} to the catalog</a>
{:else if fixed}
	<span class="text-muted text-xs whitespace-nowrap">Update to {fixed}</span>
{:else}
	<span class="text-muted text-xs">No fix yet</span>
{/if}
