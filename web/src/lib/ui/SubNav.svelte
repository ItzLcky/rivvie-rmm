<script lang="ts" module>
	export interface SubNavItem {
		value: string;
		label: string;
		count?: string;
		hidden?: boolean;
		title?: string;
	}
	export interface SubNavGroup {
		label?: string;
		items: SubNavItem[];
	}
</script>

<script lang="ts">
	import { cx } from '#lib/format.js';
	import { scrollFade } from './scrollfade.js';

	/**
	 * Section navigation for a page with many sections (an agent's): a grouped column beside
	 * the content from `lg`, a scrolling strip above it on smaller screens. Items are links to
	 * `?<param>=<value>` (so they open in a new tab), but a plain click calls `onchange` to
	 * keep the page's other URL state. Render the section for `value` yourself.
	 */
	let {
		label,
		value,
		groups,
		onchange,
		param = 'tab',
		first,
		class: klass
	}: {
		label: string;
		value: string;
		groups: SubNavGroup[];
		onchange: (value: string) => void;
		param?: string;
		/** The value that needs no URL parameter (the default section). */
		first?: string;
		class?: string;
	} = $props();

	const shown = $derived(groups.map((g) => ({ ...g, items: g.items.filter((i) => !i.hidden) })).filter((g) => g.items.length));
	const href = (v: string) => (v === first ? '?' : `?${param}=${encodeURIComponent(v)}`);
	function go(e: MouseEvent, v: string) {
		if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
		e.preventDefault();
		if (v !== value) onchange(v);
	}
</script>

<nav aria-label={label} class={cx('min-w-0', klass)}>
	<div use:scrollFade class="scroll-fade scrollbar-thin -mx-1 overflow-x-auto px-1 lg:mx-0 lg:overflow-visible lg:px-0">
		<ul class="border-border flex w-max min-w-full gap-1 border-b lg:w-auto lg:flex-col lg:gap-4 lg:border-b-0">
			{#each shown as g, gi (gi)}
				<li class="contents lg:block">
					{#if g.label}<span class="text-muted mb-1 hidden px-2.5 text-[11px] font-semibold tracking-wide uppercase lg:block">{g.label}</span>{/if}
					<ul class="contents lg:flex lg:flex-col lg:gap-0.5">
						{#each g.items as t (t.value)}
							{@const on = t.value === value}
							<li class="contents lg:block">
								<a
									href={href(t.value)}
									title={t.title}
									aria-current={on ? 'page' : undefined}
									onclick={(e) => go(e, t.value)}
									class={cx(
										'relative inline-flex h-10 shrink-0 items-center gap-2 px-2 text-sm font-medium whitespace-nowrap transition-colors',
										'after:absolute after:inset-x-0 after:-bottom-px after:h-0.5 after:rounded-t-full',
										'lg:flex lg:h-8 lg:rounded-md lg:px-2.5 lg:after:hidden',
										on ? 'text-accent after:bg-accent lg:bg-accent-soft' : 'text-muted hover:text-fg lg:hover:bg-hover'
									)}
								>
									<span class="lg:flex-1 lg:truncate">{t.label}</span>
									{#if t.count}<span class={cx('min-w-5 rounded-full px-1.5 text-center text-xs leading-5 font-medium tabular', on ? 'bg-accent text-on-accent' : 'bg-sunken text-muted')}>{t.count}</span>{/if}
								</a>
							</li>
						{/each}
					</ul>
				</li>
			{/each}
		</ul>
	</div>
</nav>
