<script lang="ts">
	import { CircleCheck, CircleAlert, Info, X } from '@lucide/svelte';
	import { fly } from 'svelte/transition';
	import { dismiss, hold, schedule, toasts } from '#lib/toast.svelte.js';
	import { cx } from '#lib/format.js';

	const icons = { success: CircleCheck, error: CircleAlert, info: Info };
	const tones = { success: 'text-success', error: 'text-danger', info: 'text-info' };
</script>

<!-- Two live regions: errors interrupt (assertive), everything else waits its turn (polite). -->
<div class="pointer-events-none fixed inset-x-0 bottom-0 z-[70] flex flex-col items-center gap-2 p-3 sm:items-end sm:p-4">
	{#each toasts as t (t.id)}
		{@const Icon = icons[t.tone]}
		<div
			transition:fly={{ y: 12, duration: 160 }}
			class="border-border bg-raised shadow-pop pointer-events-auto flex w-full max-w-sm items-start gap-2.5 rounded-lg border p-3 text-sm"
			role={t.tone === 'error' ? 'alert' : 'status'}
			aria-live={t.tone === 'error' ? 'assertive' : 'polite'}
			onmouseenter={() => hold(t.id)}
			onmouseleave={() => schedule(t.id, 4000)}
			onfocusin={() => hold(t.id)}
		>
			<Icon class={cx('mt-0.5 size-4 shrink-0', tones[t.tone])} />
			<div class="min-w-0 flex-1">
				<p class="break-words">{t.message}</p>
				{#if t.action || t.href}
					<div class="mt-1.5 flex gap-3 text-xs font-medium">
						{#if t.action}<button class="text-accent hover:underline" onclick={() => { t.action!.run(); dismiss(t.id); }}>{t.action.label}</button>{/if}
						{#if t.href}<a class="text-accent hover:underline" href={t.href.href} onclick={() => dismiss(t.id)}>{t.href.label}</a>{/if}
					</div>
				{/if}
			</div>
			<button class="text-muted hover:text-fg -m-1 flex size-6 items-center justify-center rounded" aria-label="Dismiss" onclick={() => dismiss(t.id)}><X class="size-3.5" /></button>
		</div>
	{/each}
</div>
