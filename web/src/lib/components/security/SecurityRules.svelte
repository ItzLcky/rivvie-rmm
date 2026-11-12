<script lang="ts">
	import { Ban, Eye, OctagonX, RotateCcw, Search, Siren } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { num, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { confidenceLabels, eventKindLabels, mitreUrl, modeHelp, modeLabels, severityLabels } from '#lib/security.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { RuleMode, RuleRow } from '#lib/types.js';
	import { param } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Menu, { type MenuItem } from '#lib/ui/Menu.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** The detection rules in the current content, how they're doing, and the mode each runs in. */
	let { canManage }: { canManage: boolean } = $props();

	const res = resource(() => api.get<RuleRow[]>('/security/rules'));
	let q = $state(param('q'));
	let kind = $state<'' | 'file' | 'behaviour'>('');
	let mode = $state<'' | RuleMode>('');

	const rows = $derived.by(() => {
		const f = q.trim().toLowerCase();
		return (res.data ?? [])
			.filter((r) => (!kind || r.kind === kind) && (!mode || r.effective_mode === mode) && (!f || `${r.id} ${r.name} ${r.mitre.join(' ')}`.toLowerCase().includes(f)))
			.sort((a, b) => b.hits_7d + b.audit_hits_7d - (a.hits_7d + a.audit_hits_7d) || a.id.localeCompare(b.id));
	});

	const modes: RuleMode[] = ['disabled', 'audit', 'alert', 'block'];
	const icons = { disabled: Ban, audit: Eye, alert: Siren, block: OctagonX };
	let changing = $state<{ rule: RuleRow; mode: RuleMode | null } | null>(null);
	let reason = $state('');
	let busy = $state(false);

	function items(r: RuleRow): MenuItem[] {
		return [
			{ heading: 'Run this rule in' },
			...modes.map((m) => ({
				label: modeLabels[m],
				icon: icons[m],
				disabled: m === r.effective_mode || (m === 'block' && !r.can_block),
				hint: m === r.effective_mode ? 'Current' : m === 'block' && !r.can_block ? 'Not yet' : undefined,
				title: m === 'block' && !r.can_block && r.block_blocker ? `Can’t block yet: ${r.block_blocker}` : modeHelp[m],
				onSelect: () => open(r, m)
			})),
			...(r.override_mode ? [{ separator: true as const }, { label: `Clear override (back to ${modeLabels[r.mode]})`, icon: RotateCcw, onSelect: () => open(r, null) }] : [])
		];
	}
	function open(r: RuleRow, m: RuleMode | null) {
		changing = { rule: r, mode: m };
		reason = '';
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const c = changing!;
		busy = true;
		try {
			await api.put(`/security/rules/${encodeURIComponent(c.rule.id)}`, { mode: c.mode, reason: reason.trim() });
			toast.success(c.mode ? `${c.rule.id} now runs in ${modeLabels[c.mode].toLowerCase()} mode. Agents get it within a minute.` : `${c.rule.id} is back to its shipped mode.`);
			changing = null;
			res.reload();
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

{#snippet ruleCell(r: RuleRow)}
	<div class="font-medium break-words">{r.name}</div>
	<div class="text-muted text-xs">
		<span class="font-mono">{r.id}</span> · {r.kind === 'file' ? 'File' : `Behaviour${r.event ? `, ${eventKindLabels[r.event]?.toLowerCase() ?? r.event}` : ''}`} · {severityLabels[r.severity]}
	</div>
{/snippet}
{#snippet mitreCell(r: RuleRow)}
	<span class="flex flex-wrap gap-x-3">
		{#each r.mitre as t (t)}<a class="link inline-flex min-h-6 items-center font-mono text-xs" href={mitreUrl(t)} target="_blank" rel="noopener noreferrer">{t}<span class="sr-only"> (opens attack.mitre.org)</span></a>{:else}<span class="text-muted">–</span>{/each}
	</span>
{/snippet}
{#snippet confCell(r: RuleRow)}<span class="text-muted">{confidenceLabels[r.confidence]}</span>{/snippet}
{#snippet modeCell(r: RuleRow)}
	{#if r.effective_mode === 'block'}<Badge tone="accent" icon={OctagonX}>Block</Badge>
	{:else if r.effective_mode === 'disabled'}<Badge icon={Ban}>Disabled</Badge>
	{:else if r.effective_mode === 'audit'}<span class="text-muted">Audit</span>
	{:else}<span>Alert</span>{/if}
	{#if r.override_mode}<div class="text-muted max-w-28 truncate text-xs sm:max-w-48" title={r.override_reason || undefined}>Override{r.override_reason ? `: ${r.override_reason}` : ''}</div>{/if}
{/snippet}
{#snippet hitsCell(r: RuleRow)}<span class={r.hits_7d ? 'tabular' : 'text-muted tabular'}>{num(r.hits_7d)}</span>{/snippet}
{#snippet auditCell(r: RuleRow)}<span class="text-muted tabular">{num(r.audit_hits_7d)}</span>{/snippet}
{#snippet agentsCell(r: RuleRow)}<span class="text-muted tabular">{num(r.agents_30d)}</span>{/snippet}
{#snippet fpCell(r: RuleRow)}
	{#if r.fp_rate === null}<span class="text-muted" title="No verdicts yet">–</span>
	{:else}<span class={r.fp_rate >= 0.2 ? 'text-warning font-medium tabular' : 'tabular'} title="{plural(r.true_positives, 'true positive')}, {plural(r.false_positives, 'false positive')} (30 days)">{Math.round(r.fp_rate * 100)}%</span>{/if}
{/snippet}
{#snippet actionsCell(r: RuleRow)}
	{#if canManage}<Menu label="Mode of {r.id}" items={items(r)} />{/if}
{/snippet}

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	<DataTable
		id="security-rules"
		caption="Detection rules"
		{rows}
		key={(r) => r.id}
		loading={res.loading}
		busy={res.busy}
		activeFilters={(kind ? 1 : 0) + (mode ? 1 : 0)}
		scroll={false}
		columns={[
			{ id: 'rule', label: 'Rule', cell: ruleCell, hideable: false },
			{ id: 'mitre', label: 'MITRE', cell: mitreCell, from: 'xl' },
			{ id: 'confidence', label: 'Confidence', cell: confCell, from: 'lg' },
			{ id: 'mode', label: 'Mode', cell: modeCell },
			{ id: 'hits', label: 'Hits 7d', cell: hitsCell, align: 'right', from: 'sm' },
			{ id: 'audit', label: 'Audit 7d', cell: auditCell, align: 'right', from: 'md' },
			{ id: 'agents', label: 'Agents 30d', cell: agentsCell, align: 'right', from: 'lg' },
			{ id: 'fp', label: 'FP rate', cell: fpCell, align: 'right', from: 'md' },
			{ id: 'actions', label: '', cell: actionsCell, hideable: false, align: 'right', class: 'w-12' }
		] satisfies Column<RuleRow>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} placeholder="Rule, id or technique…" aria-label="Search rules" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			<Select aria-label="Kind" class="w-full sm:w-auto" bind:value={kind} options={[{ value: '', label: 'Any kind' }, { value: 'file', label: 'File' }, { value: 'behaviour', label: 'Behaviour' }]} />
			<Select aria-label="Mode" class="w-full sm:w-auto" bind:value={mode} options={[{ value: '', label: 'Any mode' }, ...modes.map((m) => ({ value: m, label: modeLabels[m] }))]} />
		{/snippet}
		{#snippet empty()}
			<EmptyState compact title={q || kind || mode ? 'No rules match' : 'No rules yet'} description={q || kind || mode ? undefined : 'Rules arrive with signed content. Upload a bundle under Content.'} />
		{/snippet}
	</DataTable>
	<p class="text-muted mt-2 text-xs">Hits and verdicts cover the clients you can see. A rule can block once it’s high-confidence, has run 7 days in general content, and had no false positives in the last 30.</p>
{/if}

{#if changing}
	{@const c = changing}
	<Modal title={c.mode ? `Run ${c.rule.id} in ${modeLabels[c.mode].toLowerCase()} mode?` : `Clear the override on ${c.rule.id}?`} description={c.rule.name} onclose={() => (changing = null)}>
		<form id="rule-mode" class="space-y-3" onsubmit={save}>
			<p class="text-sm">
				{#if c.mode}{modeHelp[c.mode]} This applies on every agent, for every client.{:else}It goes back to the mode its content ships with: {modeLabels[c.rule.mode].toLowerCase()}.{/if}
			</p>
			{#if c.mode === 'disabled'}<p class="text-muted text-sm">Use this as the kill switch for a rule that misfires. It stays off until you clear the override, even through content updates.</p>{/if}
			<Field label="Reason" id="rm-reason" hint="Kept with the override and in the audit log.">
				<Textarea id="rm-reason" rows={2} bind:value={reason} placeholder={c.mode === 'disabled' ? 'False positives on build servers' : ''} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (changing = null)}>Cancel</Button>
			<Button variant={c.mode === 'disabled' ? 'danger' : 'primary'} type="submit" form="rule-mode" loading={busy}>{c.mode ? `Set to ${modeLabels[c.mode]}` : 'Clear override'}</Button>
		{/snippet}
	</Modal>
{/if}
