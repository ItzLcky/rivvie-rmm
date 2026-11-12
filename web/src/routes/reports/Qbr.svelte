<script lang="ts">
	import { untrack } from 'svelte';
	import { FileText } from '@lucide/svelte';
	import { qs } from '#lib/api.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { quarters } from '#lib/work/ranges.js';
	import Button, { buttonBase, buttonSizes, buttonVariants } from '#lib/ui/Button.svelte';
	import { cx } from '#lib/format.js';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Select from '#lib/ui/Select.svelte';

	let { clientId }: { clientId: string } = $props();
	const qs8 = quarters(8);
	let client = $state(untrack(() => clientId));
	let quarter = $state(qs8[1].value);
	$effect(() => {
		loadClients();
	});
	const q = $derived(qs8.find((x) => x.value === quarter) ?? qs8[1]);
	const href = $derived(client ? `/api/reports/qbr/${client}${qs({ from: q.from, to: q.to })}` : undefined);
</script>

<section class="card max-w-2xl" aria-labelledby="qbr-h">
	<header class="panel-head">
		<div>
			<h2 id="qbr-h" class="panel-title">Quarterly business review</h2>
			<p class="text-muted text-xs">A PDF for one client: tickets, response times, SLA, satisfaction, devices, patching and monitoring for the quarter.</p>
		</div>
	</header>
	<div class="grid gap-3 p-4 sm:grid-cols-2">
		<Field label="Client" id="qbr-client">
			<Combobox id="qbr-client" bind:value={client} items={clients.list.map((c) => ({ value: c.id, label: c.name }))} placeholder="Choose a client…" />
		</Field>
		<Field label="Quarter" id="qbr-quarter">
			<Select id="qbr-quarter" class="w-full" bind:value={quarter} options={qs8.map((x) => ({ value: x.value, label: x.label }))} />
		</Field>
		<div class="sm:col-span-2">
			{#if href}
				<a class={cx(buttonBase, buttonVariants.primary, buttonSizes.md)} {href} target="_blank" rel="noopener"><FileText />Open the PDF</a>
			{:else}
				<Button variant="primary" icon={FileText} disabled>Open the PDF</Button>
			{/if}
		</div>
	</div>
</section>
