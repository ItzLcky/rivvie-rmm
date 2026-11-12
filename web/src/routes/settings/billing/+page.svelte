<script lang="ts">
	import { page } from '$app/state';
	import { Lock } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { refreshSettings } from '#lib/billing/currency.js';
	import type { BillingSettings } from '#lib/billing/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { setParams } from '#lib/url.svelte.js';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Accounting from './Accounting.svelte';
	import General from './General.svelte';
	import Products from './Products.svelte';
	import Rates from './Rates.svelte';
	import WorkRoles from './WorkRoles.svelte';
	import WorkTypes from './WorkTypes.svelte';

	const settings = resource(() => api.get<BillingSettings>('/settings/billing'));
	const currency = $derived(settings.data?.currency ?? '');
	let rolesVersion = $state(0);

	// Back from the accounting provider's consent screen.
	$effect(() => {
		const q = page.url.searchParams;
		const connected = q.get('connected');
		const error = q.get('accounting_error');
		if (!connected && !error) return;
		if (connected) toast.success(`${connected === 'qbo' ? 'QuickBooks Online' : connected === 'xero' ? 'Xero' : connected} is connected.`);
		if (error) toast.error(`Couldn’t connect the accounting system: ${error}`);
		setParams({ connected: null, accounting_error: null });
	});
</script>

<svelte:head><title>Billing settings</title></svelte:head>

{#if !allowed('billing.read')}
	<div class="card"><EmptyState icon={Lock} title="No access to billing" description="Billing settings need the billing permission." /></div>
{:else}
	<div class="max-w-5xl space-y-5">
		<General res={settings} onsaved={() => { refreshSettings(); settings.reload(); }} />
		<WorkTypes {currency} />
		<WorkRoles {currency} onchange={() => rolesVersion++} />
		<Rates {currency} {rolesVersion} />
		<Products {currency} />
		<Accounting />
	</div>
{/if}
