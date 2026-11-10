<script lang="ts">
	import { OctagonAlert, ShieldAlert, ShieldOff } from '@lucide/svelte';
	import { stateHelp, stateLabels } from '#lib/security.js';
	import type { ProtectionState } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** Like the health badge: colour only when something needs a look. */
	let { state, title }: { state: ProtectionState; title?: string } = $props();
</script>

{#if state === 'threats'}
	<Badge tone="danger" icon={OctagonAlert} title={title ?? stateHelp.threats}>{stateLabels.threats}</Badge>
{:else if state === 'unprotected'}
	<Badge tone="danger" icon={ShieldOff} title={title ?? stateHelp.unprotected}>{stateLabels.unprotected}</Badge>
{:else if state === 'at_risk'}
	<Badge tone="warning" icon={ShieldAlert} title={title ?? stateHelp.at_risk}>{stateLabels.at_risk}</Badge>
{:else}
	<span class="text-muted inline-flex h-5 items-center leading-5 whitespace-nowrap" title={title ?? stateHelp[state]}>{stateLabels[state]}</span>
{/if}
