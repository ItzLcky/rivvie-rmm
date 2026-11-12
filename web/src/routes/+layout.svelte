<script lang="ts">
	import './layout.css';
	import '@fontsource-variable/geist';
	import '@fontsource-variable/geist-mono';
	import favicon from '#lib/assets/favicon.svg';
	import { Tooltip } from 'bits-ui';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { connectLive } from '#lib/live.svelte.js';
	import { trackAlerts } from '#lib/monitoring/alerts.svelte.js';
	import { trackTickets } from '#lib/servicedesk/tickets.svelte.js';
	import { loadPrefs } from '#lib/prefs.svelte.js';
	import { prefs } from '#lib/prefs.svelte.js';
	import { loadClients, withClient } from '#lib/scope.svelte.js';
	import { brand, loadCompany, session } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, User } from '#lib/types.js';
	import { cx } from '#lib/format.js';
	import Sidebar from '#lib/shell/Sidebar.svelte';
	import TopBar from '#lib/shell/TopBar.svelte';
	import CommandPalette from '#lib/shell/CommandPalette.svelte';
	import ShortcutsHelp from '#lib/shell/ShortcutsHelp.svelte';
	import { nav } from '#lib/shell/nav.js';
	import Drawer from '#lib/ui/Drawer.svelte';
	import Toaster from '#lib/ui/Toaster.svelte';
	import ConfirmHost from '#lib/ui/ConfirmHost.svelte';
	import RunScript from '#lib/components/RunScript.svelte';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	// Pages that render without the app shell or a session.
	// The client portal and survey pages are for clients, with their own sessions.
	const bare = $derived(
		page.url.pathname === '/login' ||
			page.url.pathname.startsWith('/dev/') ||
			page.url.pathname === '/portal' ||
			page.url.pathname.startsWith('/portal/') ||
			page.url.pathname.startsWith('/feedback/')
	);

	$effect(() => loadCompany());

	$effect(() => {
		if (session.loaded || bare) return;
		api.get<User>('/auth/me')
			.then((u) => {
				session.user = u;
				loadPrefs(u.preferences);
			})
			.catch(() => {
				if (!bare) goto(`/login?next=${encodeURIComponent(page.url.pathname + page.url.search)}`);
			})
			.finally(() => (session.loaded = true));
	});

	// Once signed in (and past 2FA setup): one live stream and the client list for the switcher.
	$effect(() => {
		if (session.user && !session.user.mfa_setup_required) {
			connectLive();
			loadClients();
		}
	});

	trackAlerts(() => !!session.user && !session.user.mfa_setup_required && !bare);
	trackTickets(() => !!session.user && !session.user.mfa_setup_required && !bare);

	// Admins (or everyone, per Company settings) must set up 2FA before using the dashboard.
	$effect(() => {
		if (session.user?.mfa_setup_required && page.url.pathname !== '/account') goto('/account');
	});

	let drawer = $state(false);
	let palette = $state(false);
	let shortcuts = $state(false);
	let runOn = $state<AgentSummary | null>(null);

	// Close the mobile drawer on navigation.
	$effect(() => {
		void page.url.pathname;
		drawer = false;
	});

	async function openRun(agentId: string) {
		try {
			runOn = await api.get<AgentSummary>(`/agents/${agentId}`);
		} catch (e) {
			toast.error(e);
		}
	}

	// Global shortcuts. Typing in a field only allows Ctrl/Cmd+K through.
	let pendingG = false;
	let gTimer: ReturnType<typeof setTimeout> | undefined;
	function onkeydown(e: KeyboardEvent) {
		if (!session.user || bare) return;
		if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
			e.preventDefault();
			palette = !palette;
			return;
		}
		const t = e.target as HTMLElement;
		if (e.ctrlKey || e.metaKey || e.altKey || t.closest('input, textarea, select, [contenteditable=true], .xterm, .cm-editor')) return;
		if (document.querySelector('[role=dialog], [role=alertdialog], [role=menu]')) return;
		if (pendingG) {
			pendingG = false;
			clearTimeout(gTimer);
			const item = nav.flatMap((g) => g.items).find((i) => i.key === e.key);
			if (item) {
				e.preventDefault();
				goto(item.scoped ? withClient(item.href) : item.href);
			}
			return;
		}
		if (e.key === 'g') {
			pendingG = true;
			gTimer = setTimeout(() => (pendingG = false), 1200);
		} else if (e.key === '/') {
			e.preventDefault();
			const box = document.querySelector<HTMLInputElement>('[data-search]');
			if (box) box.focus();
			else palette = true;
		} else if (e.key === '?') {
			e.preventDefault();
			shortcuts = true;
		}
	}
</script>

<svelte:window {onkeydown} />

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>{brand()}</title>
</svelte:head>

<Tooltip.Provider delayDuration={300}>
	{#if bare}
		{@render children()}
	{:else if session.user}
		<a href="#main" class="bg-accent text-on-accent sr-only z-[80] rounded-md px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2">Skip to content</a>
		<div class="flex min-h-dvh">
			<!-- The navy column runs the full page height; the rail inside it stays pinned. -->
			<div class={cx('bg-nav border-nav-border hidden shrink-0 border-r lg:block', prefs.sidebarCollapsed ? 'w-16' : 'w-64')}>
				<aside class="sticky top-0 h-dvh">
					<Sidebar />
				</aside>
			</div>
			<Drawer bind:open={drawer} title="Navigation" nav>
				<Sidebar mobile onnavigate={() => (drawer = false)} />
			</Drawer>
			<div class="flex min-w-0 flex-1 flex-col">
				{#if !session.user.mfa_setup_required}
					<TopBar onmenu={() => (drawer = true)} onsearch={() => (palette = true)} onshortcuts={() => (shortcuts = true)} />
				{/if}
				<main id="main" class="mx-auto w-full max-w-[1600px] min-w-0 flex-1 px-3 py-4 sm:px-6 sm:py-6 lg:px-8 lg:py-7">{@render children()}</main>
			</div>
		</div>
		<CommandPalette bind:open={palette} onrun={openRun} onshortcuts={() => (shortcuts = true)} />
		{#if shortcuts}<ShortcutsHelp onclose={() => (shortcuts = false)} />{/if}
		{#if runOn}<RunScript agents={[runOn]} onclose={() => (runOn = null)} />{/if}
	{:else if session.loaded}
		<!-- Redirecting to sign-in. -->
	{:else}
		<div class="flex min-h-dvh items-center justify-center" aria-busy="true" aria-label="Loading"></div>
	{/if}
	<Toaster />
	<ConfirmHost />
</Tooltip.Provider>
