<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { LogOut, Menu as MenuIcon } from '@lucide/svelte';
	import favicon from '#lib/assets/favicon.svg';
	import { cx } from '#lib/format.js';
	import { portal } from '#lib/portal/api.js';
	import { clearMe, loadMe, me } from '#lib/portal/me.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Spinner from '#lib/ui/Spinner.svelte';
	import SourceLink from '#lib/components/branding/SourceLink.svelte';
	import SupportCard from '#lib/components/branding/SupportCard.svelte';
	import { applyBranding } from '#lib/branding.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const signIn = $derived(page.url.pathname === '/portal/login');

	$effect(() => {
		if (!signIn && !me.data && !me.loading && !me.error) loadMe();
	});

	const items = $derived([
		{ href: '/portal', label: 'Tickets', match: (p: string) => p === '/portal' || p.startsWith('/portal/tickets') },
		{ href: '/portal/kb', label: 'Knowledge base', match: (p: string) => p.startsWith('/portal/kb') },
		...(me.data?.devices ? [{ href: '/portal/devices', label: 'Devices', match: (p: string) => p.startsWith('/portal/devices') }] : []),
		{ href: '/portal/account', label: 'Account', match: (p: string) => p.startsWith('/portal/account') }
	]);

	let menu = $state(false);
	$effect(() => {
		void page.url.pathname;
		menu = false;
	});

	let leaving = $state(false);
	async function signOut() {
		leaving = true;
		try {
			await portal.post('/auth/logout');
		} catch {
			// Signed out either way: the cookie is cleared or already gone.
		} finally {
			clearMe();
			leaving = false;
			await goto('/portal/login', { replace: true });
		}
	}

	const b = $derived(me.data?.branding);
	const company = $derived(b?.product_name || me.data?.company_name || 'Support');
	// The contact's client may have its own accent.
	$effect(() => {
		if (me.data) applyBranding(b);
	});
	// The header is ink in both themes: the logo made for dark backgrounds, else the light one.
	const logo = $derived(b?.logo_dark ?? b?.logo_light ?? null);
</script>

<svelte:head>
	<title>{signIn ? 'Sign in' : company} · Support portal</title>
	{#if b?.icon}<link rel="icon" href={b.icon} />{/if}
</svelte:head>

{#if signIn}
	{@render children()}
{:else}
	<div class="bg-surface flex min-h-dvh flex-col">
		<a href="#portal-main" class="bg-accent text-on-accent sr-only z-[80] rounded-md px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2">Skip to content</a>
		<header class="bg-nav text-nav-fg border-nav-border border-b">
			<div class="mx-auto flex h-14 w-full max-w-5xl items-center gap-3 px-4 sm:px-6">
				<a href="/portal" class="flex min-w-0 items-center gap-2.5 rounded-md focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none">
					{#if logo}
						<img src={logo} alt={company} class="h-8 max-w-[12rem] object-contain object-left" />
					{:else}
						<img src={b?.icon ?? favicon} alt="" class="size-7 shrink-0" />
						<span class="truncate text-[0.9375rem] font-semibold tracking-tight text-white">{company}</span>
					{/if}
					<span class="text-nav-muted hidden text-sm sm:inline">Support</span>
				</a>
				{#if me.data}
					<nav aria-label="Portal" class="ml-auto hidden md:block">
						<ul class="flex items-center gap-1">
							{#each items as i (i.href)}
								{@const active = i.match(page.url.pathname)}
								<li>
									<a
										href={i.href}
										aria-current={active ? 'page' : undefined}
										class={cx(
											'inline-flex h-8 items-center rounded-md px-3 text-sm font-medium transition-colors focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none',
											active ? 'bg-nav-active text-white' : 'text-nav-muted hover:bg-nav-hover hover:text-white'
										)}>{i.label}</a
									>
								</li>
							{/each}
							<li class="ml-2">
								<button
									type="button"
									class="text-nav-muted hover:bg-nav-hover inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-sm font-medium hover:text-white focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none disabled:opacity-60"
									disabled={leaving}
									onclick={signOut}><LogOut class="size-4" aria-hidden="true" />Sign out</button
								>
							</li>
						</ul>
					</nav>
					<button
						type="button"
						class="text-nav-fg hover:bg-nav-hover ml-auto inline-flex size-9 items-center justify-center rounded-md focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none md:hidden"
						aria-expanded={menu}
						aria-controls="portal-menu"
						aria-label="Menu"
						onclick={() => (menu = !menu)}><MenuIcon class="size-5" /></button
					>
				{/if}
			</div>
			{#if me.data && menu}
				<nav id="portal-menu" aria-label="Portal" class="border-nav-border border-t px-4 py-2 md:hidden">
					<ul class="space-y-0.5">
						{#each items as i (i.href)}
							{@const active = i.match(page.url.pathname)}
							<li>
								<a
									href={i.href}
									aria-current={active ? 'page' : undefined}
									class={cx(
										'flex h-10 items-center rounded-md px-3 text-sm font-medium focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none',
										active ? 'bg-nav-active text-white' : 'text-nav-muted hover:bg-nav-hover hover:text-white'
									)}>{i.label}</a
								>
							</li>
						{/each}
						<li>
							<button
								type="button"
								class="text-nav-muted hover:bg-nav-hover flex h-10 w-full items-center gap-2 rounded-md px-3 text-sm font-medium hover:text-white focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none"
								disabled={leaving}
								onclick={signOut}><LogOut class="size-4" aria-hidden="true" />Sign out</button
							>
						</li>
					</ul>
				</nav>
			{/if}
		</header>

		<main id="portal-main" class="mx-auto w-full max-w-5xl min-w-0 flex-1 px-4 py-6 sm:px-6 sm:py-8">
			{#if me.data}
				{@render children()}
			{:else if me.error}
				<div class="card">
					<ErrorState error={me.error} onretry={() => loadMe(true)} />
				</div>
				<p class="mt-4 text-center text-sm"><Button variant="ghost" href="/portal/login">Go to sign-in</Button></p>
			{:else}
				<div class="flex justify-center py-20"><Spinner class="size-6" /></div>
			{/if}
		</main>

		<footer class="text-muted mx-auto w-full max-w-5xl space-y-4 px-4 pb-6 text-xs sm:px-6">
			{#if b}<SupportCard support={b.support} />{/if}
			<p>
				{#if me.data}Signed in as {me.data.contact.name || me.data.contact.email} · {me.data.contact.client_name} ·{/if}
				<SourceLink href={b?.source_url} />
			</p>
		</footer>
	</div>
{/if}
