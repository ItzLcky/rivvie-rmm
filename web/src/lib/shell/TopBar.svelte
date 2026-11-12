<script lang="ts">
	import { goto } from '$app/navigation';
	import { Keyboard, LogOut, Menu as MenuIcon, Monitor, Moon, Search, Sun, UserRound } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { disconnectLive, live } from '#lib/live.svelte.js';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import { session } from '#lib/session.svelte.js';
	import { cx } from '#lib/format.js';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Kbd from '#lib/ui/Kbd.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Tooltip from '#lib/ui/Tooltip.svelte';
	import ClientSwitcher from './ClientSwitcher.svelte';

	let { onmenu, onsearch, onshortcuts }: { onmenu: () => void; onsearch: () => void; onshortcuts: () => void } = $props();

	const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);
	const initials = $derived(
		(session.user?.name ?? '?')
			.split(/\s+/)
			.map((w) => w[0])
			.slice(0, 2)
			.join('')
			.toUpperCase()
	);
	const liveText = { live: 'Live updates on', connecting: 'Connecting to live updates…', offline: 'Live updates offline: refreshing periodically' };

	const liveShort = { live: 'Live', connecting: 'Connecting', offline: 'Offline' };

	async function logout() {
		await api.post('/auth/logout').catch(() => {});
		disconnectLive();
		session.user = null;
		await goto('/login');
	}
	const theme = $derived(prefs.theme ?? 'system');
</script>

<header class="border-border bg-raised sticky top-0 z-30 flex h-14 items-center gap-2 border-b px-2 sm:gap-3 sm:px-6 lg:px-8">
	<IconButton icon={MenuIcon} label="Open navigation" class="lg:hidden" onclick={onmenu} />
	<ClientSwitcher />
	<button
		class="border-border bg-sunken text-muted hover:border-border-strong hover:text-fg flex h-8 min-w-0 flex-1 items-center gap-2.5 rounded-md border px-3 text-sm transition-colors sm:max-w-lg"
		onclick={onsearch}
	>
		<Search class="size-4 shrink-0" />
		<span class="hidden truncate min-[480px]:inline">Search agents, clients, scripts…</span>
		<span class="sr-only min-[480px]:hidden">Search</span>
		<span class="ml-auto hidden sm:inline-flex"><Kbd keys={[mac ? '⌘' : 'Ctrl', 'K']} /></span>
	</button>
	<div class="ml-auto flex items-center gap-1">
		<Tooltip text={liveText[live.status]}>
			{#snippet trigger(props)}
				<button {...props} type="button" class="text-muted flex h-8 cursor-default items-center gap-1.5 rounded-md px-2 text-xs" aria-label={liveText[live.status]}>
					<!-- Green only when connected; connecting is a neutral pulse; offline is a hollow warning ring. -->
					<span class={cx('size-2 rounded-full', live.status === 'live' ? 'bg-success' : live.status === 'connecting' ? 'bg-subtle animate-pulse' : 'border-warning border-[1.5px]')} aria-hidden="true"></span>
					<span class="hidden sm:inline" aria-hidden="true">{liveShort[live.status]}</span>
				</button>
			{/snippet}
		</Tooltip>
		<Menu
			label="Account menu"
			items={[
				{ heading: `${session.user?.name ?? ''} (${session.user?.role ?? ''})` },
				{ label: 'Account', icon: UserRound, href: '/account' },
				{ separator: true },
				{ heading: 'Theme' },
				{ label: 'System', icon: Monitor, onSelect: () => setPref('theme', 'system'), hint: theme === 'system' ? '✓' : '' },
				{ label: 'Light', icon: Sun, onSelect: () => setPref('theme', 'light'), hint: theme === 'light' ? '✓' : '' },
				{ label: 'Dark', icon: Moon, onSelect: () => setPref('theme', 'dark'), hint: theme === 'dark' ? '✓' : '' },
				{ separator: true },
				{ label: 'Keyboard shortcuts', icon: Keyboard, onSelect: onshortcuts, hint: '?' },
				{ label: 'Sign out', icon: LogOut, onSelect: logout }
			]}
		>
			{#snippet trigger(props)}
				<button {...props} class="bg-accent text-on-accent hover:ring-accent/30 ml-1 flex size-8 items-center justify-center rounded-full text-xs font-semibold transition-shadow hover:ring-4"><span aria-hidden="true">{initials}</span><span class="sr-only">Account menu</span></button>
			{/snippet}
		</Menu>
	</div>
</header>
