<script lang="ts">
	import { Paperclip, X } from '@lucide/svelte';
	import { bytes } from '#lib/format.js';
	import Button from '#lib/ui/Button.svelte';

	/** Picks files to send with a message; shows the chosen ones with a remove button each. */
	let { files = $bindable([]), id, disabled = false }: { files?: File[]; id: string; disabled?: boolean } = $props();
	let input = $state<HTMLInputElement | null>(null);

	function add(list: FileList | null) {
		if (list) files = [...files, ...Array.from(list)];
		if (input) input.value = '';
	}
</script>

<div class="space-y-2">
	<input bind:this={input} {id} type="file" multiple class="sr-only" tabindex="-1" aria-hidden="true" onchange={(e) => add(e.currentTarget.files)} />
	<Button size="sm" variant="secondary" icon={Paperclip} {disabled} onclick={() => input?.click()}>Attach files</Button>
	{#if files.length}
		<ul class="flex flex-wrap gap-1.5" aria-label="Files to send">
			{#each files as f, i (i + f.name)}
				<li class="bg-sunken border-border inline-flex h-8 max-w-full items-center gap-1.5 rounded-md border pr-1 pl-2 text-xs">
					<Paperclip class="size-3.5 shrink-0" aria-hidden="true" />
					<span class="truncate">{f.name}</span>
					<span class="text-muted shrink-0">{bytes(f.size)}</span>
					<button
						type="button"
						class="text-muted hover:text-fg hover:bg-hover focus-visible:ring-accent/40 inline-flex size-6 shrink-0 items-center justify-center rounded focus-visible:ring-2 focus-visible:outline-none"
						aria-label="Remove {f.name}"
						{disabled}
						onclick={() => (files = files.filter((_, j) => j !== i))}><X class="size-3.5" /></button
					>
				</li>
			{/each}
		</ul>
	{/if}
</div>
