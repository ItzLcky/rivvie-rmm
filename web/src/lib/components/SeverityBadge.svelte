<script lang="ts">
	import { CircleAlert, Info, OctagonAlert } from '@lucide/svelte';
	import type { Severity } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';
	import { severityLabels, severityTone } from '#lib/monitoring/labels.js';

	let { severity }: { severity: Severity } = $props();
	const icons = { critical: OctagonAlert, warning: CircleAlert, info: Info };
</script>

<Badge tone={severityTone[severity] ?? 'neutral'} icon={icons[severity]}>{severityLabels[severity] ?? severity}</Badge>
