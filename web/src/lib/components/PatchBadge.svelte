<script lang="ts">
	import { CircleCheck, CircleDashed, CircleSlash, CircleX, Clock, LoaderCircle, ShieldAlert, TriangleAlert, Unplug } from '@lucide/svelte';
	import { approvalInfo, runInfo, severityLabel, severityTone, stateInfo } from '#lib/patches.js';
	import type { Approval, PatchState, RunStatus, Severity } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** Severity, install state, approval, or an install run's status: always with a text label. */
	let {
		kind,
		value,
		title
	}:
		| { kind: 'severity'; value: Severity | null; title?: string }
		| { kind: 'state'; value: PatchState; title?: string }
		| { kind: 'approval'; value: Approval; title?: string }
		| { kind: 'run'; value: RunStatus; title?: string } = $props();

	const runIcons: Record<RunStatus, typeof CircleCheck> = {
		queued: Clock, sent: LoaderCircle, succeeded: CircleCheck, partial: TriangleAlert, failed: CircleX, lost: Unplug,
		expired: CircleDashed, cancelled: CircleSlash
	};
	const stateIcons: Record<PatchState, typeof CircleCheck> = { missing: CircleDashed, installing: LoaderCircle, installed: CircleCheck, failed: CircleX };
	const spec = $derived.by(() => {
		switch (kind) {
			case 'severity':
				return { tone: severityTone(value as Severity | null), label: severityLabel(value as Severity | null), icon: value === 'critical' ? ShieldAlert : undefined };
			case 'state':
				return { tone: stateInfo[value as PatchState][0], label: stateInfo[value as PatchState][1], icon: stateIcons[value as PatchState] };
			case 'approval':
				return { tone: approvalInfo[value as Approval][0], label: approvalInfo[value as Approval][1], icon: undefined };
			default:
				return { tone: runInfo[value as RunStatus][0], label: runInfo[value as RunStatus][1], icon: runIcons[value as RunStatus] };
		}
	});
	const spinning = $derived((kind === 'run' && value === 'sent') || (kind === 'state' && value === 'installing'));
</script>

{#if kind === 'severity' && (!value || value === 'unspecified')}
	<!-- Most updates aren't rated (every Linux package); a badge on each would be noise. -->
	<span class="text-muted" title={title ?? 'Not rated by the vendor'}><span aria-hidden="true">–</span><span class="sr-only">Unrated</span></span>
{:else}
	<Badge tone={spec.tone} icon={spec.icon} {title} class={spinning ? '[&_svg]:animate-spin' : ''}>{spec.label}</Badge>
{/if}
