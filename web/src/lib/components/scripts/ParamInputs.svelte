<script lang="ts" module>
	import type { ParamSpec } from '#lib/types.js';

	/** What `{{…}}` placeholders a text value may hold (expanded per device by the server). */
	export const PLACEHOLDERS = [
		{ value: '{{agent.hostname}}', label: 'Device hostname' },
		{ value: '{{agent.id}}', label: 'Device id' },
		{ value: '{{agent.os}}', label: 'Device OS' },
		{ value: '{{client.name}}', label: 'Client name' },
		{ value: '{{site.name}}', label: 'Site name' },
		{ value: '{{field.}}', label: 'Custom field…' }
	];

	/** `RMM_PARAM_<NAME>`: how the script reads it. */
	export const envName = (name: string) => `RMM_PARAM_${name.toUpperCase()}`;

	/** Required parameters without a value or a default. */
	export function missing(specs: ParamSpec[], values: Record<string, string>): ParamSpec[] {
		return specs.filter((s) => s.required && !(values[s.name] ?? '').trim() && (s.default == null || s.default === ''));
	}
</script>

<script lang="ts">
	import { Braces, KeyRound, X } from '@lucide/svelte';
	import type { VaultItem } from '#lib/docs/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu from '#lib/ui/Menu.svelte';
	import Select from '#lib/ui/Select.svelte';
	import VaultPicker from '../vault/VaultPicker.svelte';

	/**
	 * Inputs for a script's parameters. Values are strings, as policies store them; a secret is
	 * typed in (`vaultOnly` false) or taken from the vault as `vault:<id>` (needs `clientId`).
	 */
	let {
		specs,
		values = $bindable({}),
		clientId = null,
		vaultOnly = false,
		variables = false,
		disabled = false,
		idPrefix = 'p'
	}: {
		specs: ParamSpec[];
		values?: Record<string, string>;
		/** The one client of the devices: its vault can be used. */
		clientId?: string | null;
		/** Policies never store a secret: only vault items. */
		vaultOnly?: boolean;
		/** Offer the "Insert variable" menu on text inputs. */
		variables?: boolean;
		disabled?: boolean;
		idPrefix?: string;
	} = $props();

	let picking = $state<string | null>(null);
	let names = $state<Record<string, string>>({});
	const set = (k: string, v: string) => (values = { ...values, [k]: v });
	const placeholder = (s: ParamSpec) => (s.default != null && s.default !== '' ? `Default: ${s.default}` : s.required ? 'Required' : 'Optional');
	const isVault = (v: string | undefined) => !!v && v.startsWith('vault:');
</script>

{#if specs.length}
	<div class="space-y-3">
		{#each specs as s (s.name)}
			{@const id = `${idPrefix}-${s.name}`}
			{@const v = values[s.name] ?? ''}
			<Field label={s.label || s.name} {id} required={s.required && (s.default == null || s.default === '')}>
				{#if s.type === 'select'}
					<Select {id} value={v} {disabled} onchange={(e) => set(s.name, (e.currentTarget as HTMLSelectElement).value)}
						options={[{ value: '', label: s.default ? `Default (${s.default})` : '—' }, ...(s.choices ?? []).map((c) => ({ value: c, label: c }))]} />
				{:else if s.type === 'bool'}
					<Select {id} value={v} {disabled} onchange={(e) => set(s.name, (e.currentTarget as HTMLSelectElement).value)}
						options={[{ value: '', label: s.default == null ? '—' : `Default (${s.default ? 'yes' : 'no'})` }, { value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }]} />
				{:else if s.type === 'secret'}
					{#if isVault(v)}
						<div class="border-border flex h-8 items-center gap-2 rounded-md border px-2 text-sm">
							<KeyRound class="text-accent size-4 shrink-0" aria-hidden="true" />
							<span class="min-w-0 flex-1 truncate">{names[s.name] ?? 'Vault credential'}</span>
							{#if !disabled}<IconButton size="sm" icon={X} label="Clear {s.label || s.name}" onclick={() => set(s.name, '')} />{/if}
						</div>
					{:else}
						<div class="flex gap-2">
							{#if !vaultOnly}<Input {id} class="min-w-0 flex-1" type="password" autocomplete="off" value={v} {disabled} oninput={(e) => set(s.name, e.currentTarget.value)} placeholder={placeholder(s)} />{/if}
							{#if clientId}
								<Button icon={KeyRound} {disabled} id={vaultOnly ? id : undefined} onclick={() => (picking = s.name)}>From vault</Button>
							{:else if vaultOnly}
								<p class="text-muted text-sm" {id}>Limit this policy to one client to take this value from its vault.</p>
							{/if}
						</div>
					{/if}
				{:else}
					<div class="flex gap-2">
						<Input {id} class="min-w-0 flex-1" inputmode={s.type === 'number' ? 'decimal' : undefined} value={v} {disabled}
							oninput={(e) => set(s.name, e.currentTarget.value)} placeholder={placeholder(s)} />
						{#if variables && s.type === 'text' && !disabled}
							<Menu label="Insert variable into {s.label || s.name}" items={PLACEHOLDERS.map((p) => ({ label: p.label, hint: p.value, onSelect: () => set(s.name, v + p.value) }))}>
								{#snippet trigger(props)}<IconButton {...props} icon={Braces} label="Insert variable into {s.label || s.name}" tooltip={false} />{/snippet}
							</Menu>
						{/if}
					</div>
				{/if}
				<p class="hint">{#if s.description}{`${s.description} · `}{/if}<code class="text-xs">${envName(s.name)}</code></p>
			</Field>
		{/each}
	</div>
{/if}

{#if picking && clientId}
	{@const name = picking}
	<VaultPicker {clientId} label={specs.find((s) => s.name === name)?.label}
		onpick={(it: VaultItem) => { names = { ...names, [name]: it.name }; set(name, `vault:${it.id}`); picking = null; }}
		onclose={() => (picking = null)} />
{/if}
