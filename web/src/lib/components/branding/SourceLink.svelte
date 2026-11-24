<script lang="ts">
	import { cx } from '#lib/format.js';
	import { DEFAULT_SOURCE_URL } from '#lib/branding.js';

	/**
	 * The AGPL-3.0 §13 source offer. Shown in the rail, on the sign-in pages and in the portal
	 * footer whatever the branding says; Settings → Branding can't turn it off.
	 */
	let { href, class: klass = '' }: { href?: string | null; class?: string } = $props();
</script>

<a href={href || DEFAULT_SOURCE_URL} target="_blank" rel="noopener noreferrer" class={cx('underline-offset-2 hover:underline', klass)} title="AGPL-3.0-or-later: the source code of this server"
	>Licence and source</a
>
