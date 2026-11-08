<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { can, session } from '#lib/session.svelte.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const tabs = [
		{ href: '/settings', label: 'General' },
		{ href: '/settings/users', label: 'Users' }
	];

	$effect(() => {
		if (session.user && !can('admin')) goto('/');
	});
</script>

<h1 class="mb-4 text-xl font-semibold">Company settings</h1>
<div class="mb-4 flex gap-1 border-b border-slate-800">
	{#each tabs as t (t.href)}
		<a href={t.href} class="tab {page.url.pathname === t.href ? 'tab-active' : ''}">{t.label}</a>
	{/each}
</div>
{#if session.user && can('admin')}
	{@render children()}
{/if}
