<script lang="ts">
	import { Plus, Trash2 } from '@lucide/svelte';
	import type { ParamSpec, ParamType } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import { envName } from './ParamInputs.svelte';

	/** The parameters a script declares. Each reaches it as `RMM_PARAM_<NAME>`, never in its text. */
	let { params = $bindable([]), disabled = false }: { params?: ParamSpec[]; disabled?: boolean } = $props();

	const types: { value: ParamType; label: string }[] = [
		{ value: 'text', label: 'Text' },
		{ value: 'number', label: 'Number' },
		{ value: 'bool', label: 'Yes / no' },
		{ value: 'select', label: 'Choice' },
		{ value: 'secret', label: 'Secret' }
	];
	const NAME = /^[a-z][a-z0-9_]{0,39}$/;

	function add() {
		let n = params.length + 1;
		while (params.some((p) => p.name === `param${n}`)) n++;
		params = [...params, { name: `param${n}`, label: '', type: 'text', required: false, default: null, choices: [], description: '' }];
	}
	const update = (i: number, patch: Partial<ParamSpec>) => (params = params.map((p, j) => (j === i ? { ...p, ...patch } : p)));
</script>

<div class="card space-y-3 p-4">
	<div class="flex items-center justify-between gap-2">
		<div>
			<h2 class="text-sm font-semibold">Parameters</h2>
			<p class="hint">Asked for when it runs, and passed as environment variables: read <code>$env:RMM_PARAM_NAME</code> in PowerShell, <code>$RMM_PARAM_NAME</code> in sh, <code>%RMM_PARAM_NAME%</code> in cmd. Don't print secrets: output is stored.</p>
		</div>
		{#if !disabled}<Button size="sm" icon={Plus} onclick={add} disabled={params.length >= 30}>Add</Button>{/if}
	</div>
	{#each params as p, i (i)}
		{@const bad = !NAME.test(p.name) || params.some((q, j) => j !== i && q.name === p.name)}
		<fieldset class="border-border grid gap-3 rounded-md border p-3 sm:grid-cols-2" {disabled} aria-label="Parameter {p.name}">
			<Field label="Name" id="pe-name-{i}" error={bad ? 'Lowercase letters, digits and _, starting with a letter; unique' : undefined} hint={envName(p.name)}>
				<Input id="pe-name-{i}" class="font-mono" value={p.name} invalid={bad} oninput={(e) => update(i, { name: e.currentTarget.value.trim() })} />
			</Field>
			<Field label="Label" id="pe-label-{i}"><Input id="pe-label-{i}" value={p.label} oninput={(e) => update(i, { label: e.currentTarget.value })} placeholder={p.name} /></Field>
			<Field label="Type" id="pe-type-{i}">
				<Select id="pe-type-{i}" value={p.type} options={types} onchange={(e) => update(i, { type: (e.currentTarget as HTMLSelectElement).value as ParamType, default: null, choices: [] })} />
			</Field>
			{#if p.type === 'secret'}
				<p class="text-muted self-end pb-2 text-xs">Secrets have no default and are never shown or stored once the job has run.</p>
			{:else}
				<Field label="Default" id="pe-default-{i}">
					<Input id="pe-default-{i}" value={p.default == null ? '' : String(p.default)} oninput={(e) => update(i, { default: e.currentTarget.value === '' ? null : e.currentTarget.value })} />
				</Field>
			{/if}
			{#if p.type === 'select'}
				<Field label="Choices" id="pe-choices-{i}" hint="Comma-separated." class="sm:col-span-2">
					<Input id="pe-choices-{i}" value={(p.choices ?? []).join(', ')} oninput={(e) => update(i, { choices: e.currentTarget.value.split(',').map((c) => c.trim()).filter(Boolean) })} />
				</Field>
			{/if}
			<Field label="Description" id="pe-desc-{i}" class="sm:col-span-2"><Input id="pe-desc-{i}" value={p.description} oninput={(e) => update(i, { description: e.currentTarget.value })} /></Field>
			<div class="flex items-center justify-between sm:col-span-2">
				<Checkbox checked={p.required} onchange={(c) => update(i, { required: c })}>Required</Checkbox>
				{#if !disabled}<IconButton icon={Trash2} label="Remove parameter {p.name}" onclick={() => (params = params.filter((_, j) => j !== i))} />{/if}
			</div>
		</fieldset>
	{:else}
		<p class="text-muted text-sm">None. Add one to ask for a value each time the script runs.</p>
	{/each}
</div>
