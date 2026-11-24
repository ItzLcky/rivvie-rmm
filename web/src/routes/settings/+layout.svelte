<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { allowed, can, session } from '#lib/session.svelte.js';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	// Admins see every section; others only the sections they have a part in: Billing with
	// billing permissions, On-call for technicians (to put themselves on call).
	const limited = $derived(
		can('admin')
			? null
			: [...(can('technician') ? [{ value: '/settings/oncall', label: 'On-call' }] : []), ...(allowed('billing.read') ? [{ value: '/settings/billing', label: 'Billing' }] : [])]
	);
	const ok = $derived(!limited || limited.some((t) => t.value === page.url.pathname));
	$effect(() => {
		if (session.user && !ok) goto(limited?.[0]?.value ?? '/');
	});
</script>

<PageHeader title="Company settings" />
<Tabs
	label="Settings sections"
	class="mb-5"
	value={page.url.pathname}
	onchange={(v) => goto(v)}
	items={limited ?? [
		{ value: '/settings', label: 'General' },
		{ value: '/settings/branding', label: 'Branding' },
		{ value: '/settings/users', label: 'Users' },
		{ value: '/settings/sso', label: 'Single sign-on' },
		{ value: '/settings/notifications', label: 'Notifications' },
		{ value: '/settings/oncall', label: 'On-call' },
		{ value: '/settings/service-desk', label: 'Service desk' },
		{ value: '/settings/sla', label: 'SLAs' },
		{ value: '/settings/documentation', label: 'Documentation' },
		{ value: '/settings/fields', label: 'Fields & tags' },
		{ value: '/settings/api-keys', label: 'API' },
		{ value: '/settings/webhooks', label: 'Webhooks' },
		{ value: '/settings/siem', label: 'SIEM' },
		{ value: '/settings/billing', label: 'Billing' }
	]}
/>
{#if session.user && ok}
	{@render children()}
{/if}
