<script lang="ts">
	import { cx } from '#lib/format.js';

	/**
	 * Online/offline: a dot plus the word, never colour alone. The text stays neutral (online is
	 * the normal state and shouldn't shout); only the dot carries the colour. It inherits the
	 * cell's font size, and sits in a 20 px box like Badge so rows stay on one baseline.
	 */
	let { online, size = 'sm' }: { online: boolean; size?: 'sm' | 'md' } = $props();
</script>

<span class={cx('inline-flex h-5 items-center gap-1.5 align-middle leading-5 whitespace-nowrap', size === 'md' && 'text-sm', online ? 'text-fg' : 'text-muted')}>
	<span class={cx('inline-flex size-2 shrink-0 rounded-full', online ? 'bg-success' : 'border-subtle border-[1.5px]')}></span>
	{online ? 'Online' : 'Offline'}
</span>
