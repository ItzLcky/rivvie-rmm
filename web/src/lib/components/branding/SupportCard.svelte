<script lang="ts">
	import { Clock, Globe, Mail, Phone } from '@lucide/svelte';
	import { telHref, type Branding } from '#lib/branding.js';

	/** The branding's support contact card (portal footer, the settings preview). */
	let { support, title = 'Need help?' }: { support: Branding['support']; title?: string } = $props();
	const any = $derived(!!(support.email || support.phone || support.url || support.hours));
</script>

{#if any}
	<section class="card p-4" aria-label="Support contact">
		<h2 class="text-sm font-semibold">{title}</h2>
		<ul class="text-muted mt-2 space-y-1.5 text-sm">
			{#if support.phone}<li class="flex items-center gap-2"><Phone class="size-4 shrink-0" aria-hidden="true" /><a class="link" href={telHref(support.phone)}>{support.phone}</a></li>{/if}
			{#if support.email}<li class="flex items-center gap-2"><Mail class="size-4 shrink-0" aria-hidden="true" /><a class="link break-all" href="mailto:{support.email}">{support.email}</a></li>{/if}
			{#if support.url}<li class="flex items-center gap-2"><Globe class="size-4 shrink-0" aria-hidden="true" /><a class="link break-all" href={support.url} target="_blank" rel="noopener noreferrer">{support.url.replace(/^https?:\/\//, '')}</a></li>{/if}
			{#if support.hours}<li class="flex items-center gap-2"><Clock class="size-4 shrink-0" aria-hidden="true" /><span>{support.hours}</span></li>{/if}
		</ul>
	</section>
{/if}
