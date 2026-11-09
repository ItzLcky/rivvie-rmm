<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { can, session } from '#lib/session.svelte.js';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	$effect(() => {
		if (session.user && !can('admin')) goto('/');
	});
</script>

<PageHeader title="Company settings" />
<Tabs
	label="Settings sections"
	class="mb-5"
	value={page.url.pathname}
	onchange={(v) => goto(v)}
	items={[
		{ value: '/settings', label: 'General' },
		{ value: '/settings/users', label: 'Users' },
		{ value: '/settings/notifications', label: 'Notifications' },
		{ value: '/settings/service-desk', label: 'Service desk' }
	]}
/>
{#if session.user && can('admin')}
	{@render children()}
{/if}
