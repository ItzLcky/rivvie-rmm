<script lang="ts">
	import { ChevronRight } from '@lucide/svelte';
	import { cx, datetime } from '#lib/format.js';
	import { eventKindLabels, eventSummary } from '#lib/security.js';
	import type { Proc, TelemetryEvent } from '#lib/types.js';
	import CodeBlock from '#lib/ui/CodeBlock.svelte';

	/** Telemetry events as rows; each expands to its details and raw JSON. */
	let {
		events,
		caption = 'Events',
		highlight,
		showDate = false
	}: {
		events: TelemetryEvent[];
		caption?: string;
		/** Marks one event (e.g. the one that triggered a detection). */
		highlight?: (e: TelemetryEvent) => boolean;
		/** Show the date as well as the time (results spanning days). */
		showDate?: boolean;
	} = $props();

	let open = $state(new Set<number>());
	function toggle(i: number) {
		const s = new Set(open);
		if (s.has(i)) s.delete(i);
		else s.add(i);
		open = s;
	}
	const time = (ts: string) =>
		showDate ? datetime(ts) : new Date(ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
</script>

{#snippet proc(label: string, p: Proc)}
	<dt>{label}</dt>
	<dd>
		<span class="font-medium">{p.name}</span> <span class="text-muted tabular">PID {p.pid}{p.ppid ? ` · parent ${p.ppid}` : ''}</span>
		{#if p.user}<span class="text-muted">{' · '}{p.user}</span>{/if}
		{#if p.command_line}<div class="font-mono text-xs break-all">{p.command_line}</div>{/if}
		{#if p.exe && p.exe !== p.command_line}<div class="text-muted font-mono text-xs break-all">{p.exe}</div>{/if}
		{#if p.sha256}<div class="text-muted font-mono text-xs break-all">SHA-256 {p.sha256}</div>{/if}
	</dd>
{/snippet}

<div class="overflow-x-auto">
	<table class="table table-fixed" aria-label={caption}>
		<colgroup><col class="w-9" /><col class={showDate ? 'w-44' : 'w-24'} /><col class="hidden w-24 sm:table-column" /><col /></colgroup>
		<thead>
			<tr><th><span class="sr-only">Details</span></th><th>Time</th><th class="hidden sm:table-cell">Kind</th><th>Event</th></tr>
		</thead>
		<tbody>
			{#each events as e, i (i)}
				{@const hl = highlight?.(e)}
				<tr class={cx(hl && '[&>td]:bg-danger-soft/60')}>
					<td class="!pr-0">
						<button
							type="button"
							class="text-muted hover:bg-hover hover:text-fg inline-flex size-6 cursor-pointer items-center justify-center rounded"
							aria-expanded={open.has(i)}
							aria-label="Details of event {i + 1}"
							onclick={() => toggle(i)}
						>
							<ChevronRight class={cx('size-4 transition-transform', open.has(i) && 'rotate-90')} />
						</button>
					</td>
					<td class="text-muted text-xs whitespace-nowrap tabular" title={datetime(e.ts)}>{time(e.ts)}</td>
					<td class="hidden text-xs sm:table-cell">{eventKindLabels[e.kind] ?? e.kind}</td>
					<td class="min-w-0">
						<div class="text-xs">
							<span class="font-medium">{e.action}</span>
							<span class="text-muted sm:hidden">{' · '}{eventKindLabels[e.kind] ?? e.kind}</span>
							{#if e.process && e.kind !== 'process'}<span class="text-muted">{' · '}{e.process.name} ({e.process.pid})</span>{/if}
							{#if hl}<span class="text-danger font-medium">{' · '}detected</span>{/if}
						</div>
						<div class="truncate font-mono text-xs" title={eventSummary(e)}>{eventSummary(e)}</div>
					</td>
				</tr>
				{#if open.has(i)}
					<tr>
						<td></td>
						<td colspan="3" class="min-w-0">
							<dl class="dl mb-3 text-xs">
								<dt>When</dt><dd>{datetime(e.ts)} <span class="text-muted">· seq {e.seq}</span></dd>
								{#if e.process}{@render proc('Process', e.process)}{/if}
								{#if e.parent}{@render proc('Parent', e.parent)}{/if}
								{#if e.file}
									<dt>File</dt>
									<dd class="font-mono break-all">{e.file.path}{#if e.file.old_path}<div class="text-muted">was {e.file.old_path}</div>{/if}{#if e.file.sha256}<div class="text-muted">SHA-256 {e.file.sha256}</div>{/if}</dd>
								{/if}
								{#if e.network}
									<dt>Connection</dt>
									<dd class="font-mono">{e.network.protocol} {e.network.local_addr}:{e.network.local_port}{e.network.remote_addr ? ` → ${e.network.remote_addr}:${e.network.remote_port}` : ''}</dd>
								{/if}
								{#if e.registry}
									<dt>Registry</dt>
									<dd class="font-mono break-all">{e.registry.key}{#if e.registry.value}<div>{e.registry.value}{e.registry.data ? ` = ${e.registry.data}` : ''}</div>{/if}</dd>
								{/if}
								{#if e.module}<dt>Module</dt><dd class="font-mono break-all">{e.module.path ?? e.module.name}</dd>{/if}
							</dl>
							<CodeBlock label="JSON" code={JSON.stringify(e, null, 2)} class="max-w-full" />
						</td>
					</tr>
				{/if}
			{/each}
		</tbody>
	</table>
</div>
