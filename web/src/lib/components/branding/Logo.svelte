<script lang="ts">
	import { cx } from '#lib/format.js';
	import type { Branding } from '#lib/branding.js';

	/**
	 * The branding logo for a page surface: the light-background logo in the light theme and the
	 * dark-background one in the dark theme (each falls back to the other). Nothing when none is
	 * uploaded; the caller shows its own mark then.
	 */
	let { branding, alt, class: klass = '' }: { branding: Branding | null | undefined; alt: string; class?: string } = $props();
	const light = $derived(branding?.logo_light ?? branding?.logo_dark ?? null);
	const dark = $derived(branding?.logo_dark ?? branding?.logo_light ?? null);
</script>

{#if light && dark}
	{#if light === dark}
		<img src={light} {alt} class={cx('object-contain object-left', klass)} />
	{:else}
		<img src={light} {alt} class={cx('logo-light object-contain object-left', klass)} />
		<img src={dark} {alt} class={cx('logo-dark object-contain object-left', klass)} />
	{/if}
{/if}

<style>
	.logo-dark {
		display: none;
	}
	:global([data-theme='dark']) .logo-dark {
		display: block;
	}
	:global([data-theme='dark']) .logo-light {
		display: none;
	}
</style>
