<script lang="ts">
	import './layout.css';
	import favicon from '#lib/assets/favicon.svg';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { brand, can, company, loadCompany, session } from '#lib/session.svelte.js';
	import type { User } from '#lib/types.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const isLogin = $derived(page.url.pathname === '/login');

	$effect(() => loadCompany());

	$effect(() => {
		if (session.loaded) return;
		api.get<User>('/auth/me')
			.then((u) => (session.user = u))
			.catch(() => {
				if (!isLogin) goto(`/login?next=${encodeURIComponent(page.url.pathname)}`);
			})
			.finally(() => (session.loaded = true));
	});

	// Admins (or everyone, per Company settings) must set up 2FA before using the dashboard.
	$effect(() => {
		if (session.user?.mfa_setup_required && page.url.pathname !== '/account') goto('/account');
	});

	const nav = $derived([
		{ href: '/', label: 'Dashboard', show: true },
		{ href: '/agents', label: 'Agents', show: true },
		{ href: '/clients', label: 'Clients & Sites', show: true },
		{ href: '/scripts', label: 'Scripts', show: true },
		{ href: '/jobs', label: 'Job history', show: true },
		{ href: '/audit', label: 'Audit log', show: can('admin') }
	]);

	function active(href: string) {
		return href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(href);
	}

	async function logout() {
		await api.post('/auth/logout');
		session.user = null;
		await goto('/login');
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>{brand()}</title>
</svelte:head>

{#if isLogin}
	{@render children()}
{:else if session.user}
	<div class="flex min-h-screen">
		<aside class="sticky top-0 flex h-screen w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-950">
			<a href="/" class="flex items-center gap-2 px-4 py-4 font-semibold tracking-tight">
				<img src={favicon} alt="" class="size-6" />
				<span class="truncate">{company.name || 'RMM'}</span>
			</a>
			<nav class="flex-1 space-y-0.5 px-2">
				{#each nav.filter((n) => n.show) as n (n.href)}
					<a href={n.href} class="block rounded-md px-3 py-1.5 text-sm {active(n.href) ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'}">{n.label}</a>
				{/each}
			</nav>
			<div class="border-t border-slate-800 p-3 text-xs">
				{#if can('admin')}
					<a href="/settings" class="-mx-1 mb-2 block rounded-md px-1 py-1 text-sm {active('/settings') ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'}">Company settings</a>
				{/if}
				<a href="/account" class="block rounded-md px-1 py-0.5 -mx-1 hover:bg-slate-900 {active('/account') ? 'bg-slate-800' : ''}">
					<div class="truncate text-slate-200">{session.user.name}</div>
					<div class="truncate text-slate-500">{session.user.email} · {session.user.role}</div>
				</a>
				<button class="mt-2 text-slate-400 hover:text-slate-100" onclick={logout}>Sign out</button>
			</div>
		</aside>
		<main class="min-w-0 flex-1 p-6">{@render children()}</main>
	</div>
{/if}
