<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { VulnProduct } from '#lib/vulns.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Adds or edits a Windows product mapping: installed titles to an NVD CPE vendor and product. */
	let {
		product,
		title = '',
		publisher = null,
		onclose,
		ondone
	}: { product: VulnProduct | null; title?: string; publisher?: string | null; onclose: () => void; ondone: () => void } = $props();

	// The form starts from the mapping (or the title being mapped) and doesn't follow later prop changes.
	const init = untrack(() => ({
		vendor: product?.vendor ?? '',
		name: product?.name ?? title,
		cpe: product?.product ?? '',
		patterns: product ? product.name_patterns.join('\n') : title,
		pub: product?.publisher_pattern ?? (publisher ? `${publisher.split(/[ ,]/)[0]}*` : ''),
		packageId: product?.package_id ?? ''
	}));
	let vendor = $state(init.vendor);
	let name = $state(init.name);
	let cpe = $state(init.cpe);
	let patterns = $state(init.patterns);
	let pub = $state(init.pub);
	let packageId = $state(init.packageId);
	let busy = $state(false);
	const packages = resource(() => api.get<{ id: string; name: string; client_id: string | null }[]>('/software/packages'));

	async function save() {
		busy = true;
		const body = {
			vendor: vendor.trim(), product: cpe.trim(), name: name.trim(), name_patterns: patterns.split('\n').map((p) => p.trim()).filter(Boolean),
			publisher_pattern: pub.trim() || null, package_id: packageId || null
		};
		const ok = await attempt(() => (product ? api.put(`/vulnerabilities/products/${product.id}`, body) : api.post('/vulnerabilities/products', body)), product ? 'Mapping saved.' : 'Product mapped.');
		busy = false;
		if (ok) ondone();
	}
</script>

<Modal title={product ? `Edit ${product.name}` : 'Map a Windows application'} description="NVD names products by CPE: cpe:2.3:a:<vendor>:<product>. Look it up in the NVD's CPE search." {onclose}>
	<div class="space-y-4">
		<Field label="Name" id="vp-name"><Input id="vp-name" bind:value={name} /></Field>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="CPE vendor" id="vp-vendor"><Input id="vp-vendor" class="font-mono text-[13px]" bind:value={vendor} placeholder="google" /></Field>
			<Field label="CPE product" id="vp-product"><Input id="vp-product" class="font-mono text-[13px]" bind:value={cpe} placeholder="chrome" /></Field>
		</div>
		<Field label="Installed titles" id="vp-patterns" hint="One per line, as Apps & features shows them; * matches anything. The longest matching pattern wins.">
			<Textarea id="vp-patterns" rows={3} class="font-mono text-[13px]" bind:value={patterns} />
		</Field>
		<Field label="Publisher" id="vp-pub" hint="Optional; * matches anything. Stops look-alike titles from other publishers matching.">
			<Input id="vp-pub" bind:value={pub} />
		</Field>
		<Field label="Catalog package" id="vp-pkg" hint="Offers “Upgrade with” on its findings.">
			<Select id="vp-pkg" bind:value={packageId} options={[{ value: '', label: 'None' }, ...(packages.data ?? []).filter((p) => !p.client_id).map((p) => ({ value: p.id, label: p.name }))]} />
		</Field>
	</div>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" loading={busy} disabled={!vendor.trim() || !cpe.trim() || !patterns.trim()} onclick={save}>Save</Button>
	{/snippet}
</Modal>
