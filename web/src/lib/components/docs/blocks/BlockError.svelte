<script lang="ts">
	import { TriangleAlert } from '@lucide/svelte';
	import type { BlockSegment } from '#lib/docs/blocks.js';

	/** A block that can't be shown: its source as written, with what's wrong in one line. */
	let { seg, message }: { seg: BlockSegment; message: string } = $props();
</script>

<div class="doc-block border-warning/50 overflow-hidden rounded-md border">
	<p class="bg-warning-soft text-warning flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium">
		<TriangleAlert class="size-3.5 shrink-0" aria-hidden="true" />
		<span>This {seg.name} block can’t be shown: {message}</span>
	</p>
	<pre class="bg-sunken overflow-x-auto px-3 py-2 font-mono text-xs leading-relaxed">```{seg.name}{seg.arg ? ` ${seg.arg}` : ''}
{seg.body}
```</pre>
</div>
