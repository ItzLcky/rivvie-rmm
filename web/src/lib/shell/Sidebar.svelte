<script lang="ts">
	import { page } from '$app/state';
	import { PanelLeftClose, PanelLeftOpen } from '@lucide/svelte';
	import favicon from '#lib/assets/favicon.svg';
	import { cx } from '#lib/format.js';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import { withClient } from '#lib/scope.svelte.js';
	import { allowed, can, company } from '#lib/session.svelte.js';
	import Tooltip from '#lib/ui/Tooltip.svelte';
	import { alertCounts } from '#lib/monitoring/alerts.svelte.js';
	import { ticketCounts } from '#lib/servicedesk/tickets.svelte.js';
	import { isActive, nav } from './nav';

	/**
	 * The navigation rail: dark navy in both themes. `collapsed` shows icons only; the mobile
	 * drawer always renders it expanded.
	 */
	let { mobile = false, onnavigate }: { mobile?: boolean; onnavigate?: () => void } = $props();
	const collapsed = $derived(!mobile && !!prefs.sidebarCollapsed);
	const openAlerts = $derived(alertCounts.critical + alertCounts.warning + alertCounts.info);
	const b = $derived(company.branding);
	// The rail is ink in both themes: the logo made for dark backgrounds, else the light one.
	const logo = $derived(b?.logo_dark ?? b?.logo_light ?? null);
	const groups = $derived(nav.map((g) => ({ ...g, items: g.items.filter((i) => (!i.role || can(i.role)) && (!i.perm || allowed(i.perm))) })).filter((g) => g.items.length));
</script>

<div class={cx('nav-rail bg-nav text-nav-fg flex h-full flex-col', collapsed ? 'w-16' : 'w-64')}>
	<a
		href={withClient('/')}
		class={cx('border-nav-border flex h-14 shrink-0 items-center gap-3 border-b', collapsed ? 'justify-center' : 'px-5')}
		onclick={onnavigate}
	>
		{#if collapsed || !logo}<img src={b?.icon ?? favicon} alt="" class="size-7 shrink-0" />{/if}
		{#if !collapsed && logo}
			<img src={logo} alt={b?.product_name || company.name || 'Home'} class="h-8 max-w-[11rem] object-contain object-left" />
		{:else if !collapsed}
			<span class="min-w-0 leading-tight">
				<span class="font-display block truncate text-base font-semibold text-white">{b?.product_name || company.name || 'Rivvie'}</span>
				<span class="text-nav-muted block truncate text-xs">Remote management</span>
			</span>
		{/if}
	</a>
	<nav aria-label="Main" class="nav-scroll flex-1 overflow-y-auto px-3 pt-2 pb-4">
		{#each groups as g (g.label)}
			<div class="mt-5 first:mt-2">
				{#if collapsed}
					<div class="bg-nav-border mx-2 mb-3 h-px first:hidden" aria-hidden="true"></div>
				{:else}
					<div class="text-nav-label px-3 pb-2 text-xs font-medium">{g.label}</div>
				{/if}
				<ul class="space-y-0.5">
					{#each g.items as item (item.href)}
						{@const on = isActive(item.href, page.url.pathname)}
						<li>
							<Tooltip text={item.label} side="right" disabled={!collapsed}>
								{#snippet trigger(props)}
									<a
										{...props}
										href={item.scoped ? withClient(item.href) : item.href}
										aria-current={on ? 'page' : undefined}
										aria-label={collapsed ? item.label : undefined}
										onclick={onnavigate}
										class={cx(
											'relative flex h-9 items-center gap-3 rounded-md text-sm transition-colors duration-150 [&_svg]:size-[18px] [&_svg]:shrink-0',
											collapsed ? 'justify-center' : 'px-3',
											on
												? 'bg-nav-active font-medium text-white before:bg-nav-indicator before:absolute before:top-1.5 before:bottom-1.5 before:-left-3 before:w-[3px] before:rounded-r-full'
												: 'text-nav-muted hover:bg-nav-hover hover:text-nav-fg'
										)}
									>
										<span class="relative flex">
											<item.icon />
											{#if collapsed && item.badge === 'alerts' && openAlerts}<span class={cx('ring-nav absolute -top-0.5 -right-0.5 size-2 rounded-full ring-2', alertCounts.critical ? 'bg-[#f2756c]' : 'bg-[#e3a84a]')} aria-hidden="true"></span>{/if}
											{#if collapsed && item.badge === 'tickets' && ticketCounts.unassigned}<span class="ring-nav bg-nav-indicator absolute -top-0.5 -right-0.5 size-2 rounded-full ring-2" aria-hidden="true"></span>{/if}
										</span>
										{#if !collapsed}<span class="truncate">{item.label}</span>{/if}
										{#if item.badge === 'alerts' && openAlerts}
											<span class={cx('tabular ml-auto min-w-5 rounded-full px-1.5 text-center text-[0.6875rem] leading-5 font-semibold', collapsed && 'sr-only', alertCounts.critical ? 'bg-[#e5484d] text-white' : 'bg-[#e3a84a] text-[#1f1400]')}>
												{openAlerts > 999 ? '999+' : openAlerts}<span class="sr-only"> open</span>
											</span>
										{:else if item.badge === 'tickets' && ticketCounts.unassigned}
											<span class={cx('tabular ml-auto min-w-5 rounded-full bg-white/12 px-1.5 text-center text-[0.6875rem] leading-5 font-semibold text-white', collapsed && 'sr-only')}>
												{ticketCounts.unassigned > 999 ? '999+' : ticketCounts.unassigned}<span class="sr-only"> unassigned</span>
											</span>
										{/if}
									</a>
								{/snippet}
							</Tooltip>
						</li>
					{/each}
				</ul>
			</div>
		{/each}
	</nav>
	{#if !mobile}
		<div class={cx('border-nav-border border-t p-3', collapsed && 'flex justify-center px-2')}>
			<button
				class={cx('text-nav-muted hover:bg-nav-hover hover:text-nav-fg flex h-9 items-center gap-3 rounded-md text-sm transition-colors [&_svg]:size-[18px]', collapsed ? 'w-10 justify-center' : 'w-full px-3')}
				onclick={() => setPref('sidebarCollapsed', !collapsed)}
				aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
			>
				{#if collapsed}<PanelLeftOpen />{:else}<PanelLeftClose /><span>Collapse</span>{/if}
			</button>
		</div>
	{/if}
</div>

<style>
	.nav-rail :global(:focus-visible) {
		outline-color: var(--nav-indicator);
	}
	.nav-scroll {
		scrollbar-width: thin;
		scrollbar-color: rgb(255 255 255 / 0.15) transparent;
	}
</style>
