<script lang="ts">
	import { page } from '$app/state';
	import { PanelLeftClose, PanelLeftOpen } from '@lucide/svelte';
	import favicon from '#lib/assets/favicon.svg';
	import { cx } from '#lib/format.js';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import { withClient } from '#lib/scope.svelte.js';
	import { can, company } from '#lib/session.svelte.js';
	import Tooltip from '#lib/ui/Tooltip.svelte';
	import { isActive, nav } from './nav';

	/** `collapsed` shows icons only; the mobile drawer always renders it expanded. */
	let { mobile = false, onnavigate }: { mobile?: boolean; onnavigate?: () => void } = $props();
	const collapsed = $derived(!mobile && !!prefs.sidebarCollapsed);
	const groups = $derived(nav.map((g) => ({ ...g, items: g.items.filter((i) => !i.role || can(i.role)) })).filter((g) => g.items.length));
</script>

<div class={cx('flex h-full flex-col', collapsed ? 'w-14' : 'w-60')}>
	<a href={withClient('/')} class={cx('flex h-12 shrink-0 items-center gap-2.5 font-semibold tracking-tight', collapsed ? 'justify-center' : 'px-4')} onclick={onnavigate}>
		<img src={favicon} alt="" class="size-6 shrink-0" />
		{#if !collapsed}<span class="truncate">{company.name || 'RMM'}</span>{/if}
	</a>
	<nav aria-label="Main" class="scrollbar-thin flex-1 overflow-y-auto px-2 pb-3">
		{#each groups as g (g.label)}
			<div class="mt-3 first:mt-1">
				{#if collapsed}
					<div class="bg-border mx-2 mb-2 h-px first:hidden" aria-hidden="true"></div>
				{:else}
					<div class="text-muted px-2 pb-1 text-[11px] font-medium tracking-wide uppercase">{g.label}</div>
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
											'flex h-8 items-center gap-2.5 rounded-md text-sm transition-colors [&_svg]:size-[18px] [&_svg]:shrink-0',
											collapsed ? 'justify-center' : 'px-2',
											on ? 'bg-accent-soft text-accent font-medium' : 'text-muted hover:bg-hover hover:text-fg'
										)}
									>
										<item.icon />
										{#if !collapsed}<span class="truncate">{item.label}</span>{/if}
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
		<div class={cx('border-border border-t p-2', collapsed && 'flex justify-center')}>
			<button
				class={cx('text-muted hover:bg-hover hover:text-fg flex h-8 items-center gap-2.5 rounded-md text-sm [&_svg]:size-[18px]', collapsed ? 'w-10 justify-center' : 'w-full px-2')}
				onclick={() => setPref('sidebarCollapsed', !collapsed)}
				aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
			>
				{#if collapsed}<PanelLeftOpen />{:else}<PanelLeftClose /><span>Collapse</span>{/if}
			</button>
		</div>
	{/if}
</div>
