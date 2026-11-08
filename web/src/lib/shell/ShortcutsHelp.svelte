<script lang="ts">
	import Modal from '#lib/ui/Modal.svelte';
	import Kbd from '#lib/ui/Kbd.svelte';
	import { nav } from './nav';

	let { onclose }: { onclose: () => void } = $props();
	const mac = /Mac|iPhone|iPad/.test(navigator.platform);
	const groups = [
		{
			title: 'Anywhere',
			rows: [
				[[mac ? '⌘' : 'Ctrl', 'K'], 'Search and commands'],
				[['/'], 'Focus the page’s search box (or open search)'],
				[['?'], 'This list'],
				[['Esc'], 'Close a dialog or menu']
			]
		},
		{ title: 'Go to', rows: nav.flatMap((g) => g.items).filter((i) => i.key).map((i) => [['g', i.key!], i.label]) },
		{
			title: 'Lists',
			rows: [
				[['j'], 'Next row'],
				[['k'], 'Previous row'],
				[['Enter'], 'Open the row'],
				[['x'], 'Select the row']
			]
		}
	] as { title: string; rows: [string[], string][] }[];
</script>

<Modal title="Keyboard shortcuts" {onclose} size="md">
	<div class="grid gap-6 sm:grid-cols-2">
		{#each groups as g (g.title)}
			<section>
				<h3 class="text-muted mb-2 text-xs font-medium tracking-wide uppercase">{g.title}</h3>
				<dl class="space-y-1.5">
					{#each g.rows as [keys, what] (what)}
						<div class="flex items-center justify-between gap-3 text-sm"><dt>{what}</dt><dd><Kbd {keys} /></dd></div>
					{/each}
				</dl>
			</section>
		{/each}
	</div>
</Modal>
