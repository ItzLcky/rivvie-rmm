<script lang="ts">
	import { BellRing, Clock, LifeBuoy, Menu, Monitor } from '@lucide/svelte';
	import { page } from '$app/state';
	import { alertCounts } from '#lib/monitoring/alerts.svelte.js';
	import { cx } from '#lib/format.js';

	/** The installed app's tab bar on phones (shown only in standalone display mode). */
	let { onmore }: { onmore: () => void } = $props();
	const tabs = [
		{ href: '/alerts', label: 'Alerts', icon: BellRing },
		{ href: '/tickets', label: 'Tickets', icon: LifeBuoy },
		{ href: '/time', label: 'Time', icon: Clock },
		{ href: '/agents', label: 'Devices', icon: Monitor }
	];
	const current = (href: string) => page.url.pathname === href || page.url.pathname.startsWith(`${href}/`);
	const critical = $derived(alertCounts.loaded ? alertCounts.critical : 0);
</script>

<nav aria-label="App tabs" class="bg-surface border-border fixed inset-x-0 bottom-0 z-40 border-t pb-[env(safe-area-inset-bottom)] lg:hidden">
	<ul class="grid grid-cols-5">
		{#each tabs as t (t.href)}
			<li>
				<a href={t.href} aria-current={current(t.href) ? 'page' : undefined} class={cx('flex min-h-14 flex-col items-center justify-center gap-0.5 text-xs', current(t.href) ? 'text-accent font-medium' : 'text-muted')}>
					<span class="relative">
						<t.icon class="size-5" aria-hidden="true" />
						{#if t.href === '/alerts' && critical}<span class="bg-danger text-on-accent absolute -top-1.5 -right-2.5 min-w-4 rounded-full px-1 text-[10px] leading-4">{critical}</span>{/if}
					</span>
					{t.label}
				</a>
			</li>
		{/each}
		<li>
			<button type="button" class="text-muted flex min-h-14 w-full flex-col items-center justify-center gap-0.5 text-xs" onclick={onmore}>
				<Menu class="size-5" aria-hidden="true" />More
			</button>
		</li>
	</ul>
</nav>
