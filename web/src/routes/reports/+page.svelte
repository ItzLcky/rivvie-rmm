<script lang="ts">
	import { CalendarClock } from '@lucide/svelte';
	import { currentClient, clientId } from '#lib/scope.svelte.js';
	import { allowed, can } from '#lib/session.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { loadCurrency } from '#lib/work/money.svelte.js';
	import { presetRange, presets, type Preset } from '#lib/work/ranges.js';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import type { ScheduledReport } from '#lib/work/types.js';
	import DeskReport from './DeskReport.svelte';
	import ProfitReport from './ProfitReport.svelte';
	import Qbr from './Qbr.svelte';
	import ScheduleDrawer from './ScheduleDrawer.svelte';
	import Scheduled from './Scheduled.svelte';
	import UtilisationReport from './UtilisationReport.svelte';

	const canUtil = $derived(allowed('time.approve') || allowed('billing.read'));
	const canProfit = $derived(allowed('billing.read'));
	const tabs = $derived([
		{ value: 'desk', label: 'Service desk' },
		{ value: 'utilisation', label: 'Utilisation', hidden: !canUtil },
		{ value: 'profitability', label: 'Profitability', hidden: !canProfit },
		{ value: 'qbr', label: 'Business review' },
		{ value: 'scheduled', label: 'Scheduled', hidden: !can('technician') }
	]);
	const tabReport: Record<string, ScheduledReport> = { desk: 'service_desk', utilisation: 'utilisation', profitability: 'profitability', qbr: 'qbr' };
	let scheduling = $state(false);
	const tab = $derived(tabs.some((t) => t.value === param('tab') && !t.hidden) ? param('tab') : 'desk');

	const isDay = (s: string) => /^\d{4}-\d{2}-\d{2}$/.test(s);
	const preset = $derived((presets.some((p) => p.value === param('range')) ? param('range') : isDay(param('from')) ? 'custom' : 'last30') as Preset | 'custom');
	const range = $derived(
		preset === 'custom' ? { from: param('from'), to: isDay(param('to')) ? param('to') : presetRange('last30').to } : presetRange(preset)
	);
	const valid = $derived(isDay(range.from) && isDay(range.to) && range.from <= range.to);
	const scoped = $derived(currentClient());
	$effect(() => {
		loadCurrency();
	});

	function choose(v: string) {
		if (v === 'custom') setParams({ range: null, from: range.from, to: range.to });
		else setParams({ range: v === 'last30' ? null : v, from: null, to: null });
	}
</script>

<PageHeader title="Reports" description={scoped ? `Figures for ${scoped.name} (the service desk report follows the client switcher).` : 'Service desk performance, technician utilisation, client profitability and quarterly business reviews.'} />

<div class="mb-4 flex flex-wrap items-center gap-2">
	<Tabs label="Reports" class="min-w-0 flex-1" value={tab} onchange={(v) => setParams({ tab: v === 'desk' ? null : v })} items={tabs} />
	{#if tab !== 'scheduled' && can('technician')}<Button size="sm" icon={CalendarClock} onclick={() => (scheduling = true)}>Schedule…</Button>{/if}
</div>

{#if scheduling}
	<ScheduleDrawer report={tabReport[tab]} clientId={clientId()} onclose={() => (scheduling = false)} onsaved={() => ((scheduling = false), setParams({ tab: 'scheduled' }))} />
{/if}

{#if tab === 'scheduled'}
	<Scheduled clientId={clientId()} />
{:else if tab !== 'qbr'}
	<form class="mb-5 flex flex-wrap items-end gap-2" aria-label="Date range" onsubmit={(e) => e.preventDefault()}>
		<div>
			<label class="label" for="rp-range">Period</label>
			<Select id="rp-range" class="w-full sm:w-44" value={preset} onchange={(e) => choose(e.currentTarget.value)} options={[...presets, { value: 'custom', label: 'Custom…' }]} />
		</div>
		<div>
			<label class="label" for="rp-from">From</label>
			<Input id="rp-from" type="date" class="w-40" value={range.from} max={range.to} onchange={(e) => setParams({ range: null, from: e.currentTarget.value, to: range.to })} />
		</div>
		<div>
			<label class="label" for="rp-to">To</label>
			<Input id="rp-to" type="date" class="w-40" value={range.to} min={range.from} onchange={(e) => setParams({ range: null, from: range.from, to: e.currentTarget.value })} />
		</div>
	</form>
	{#if !valid}
		<p class="text-danger text-sm" role="alert">Choose a start date on or before the end date.</p>
	{/if}
{/if}

{#if tab === 'qbr'}
	<Qbr clientId={clientId()} />
{:else if tab !== 'scheduled' && valid}
	{#if tab === 'utilisation'}
		<UtilisationReport from={range.from} to={range.to} />
	{:else if tab === 'profitability'}
		<ProfitReport from={range.from} to={range.to} />
	{:else}
		<DeskReport from={range.from} to={range.to} clientId={clientId()} />
	{/if}
{/if}
