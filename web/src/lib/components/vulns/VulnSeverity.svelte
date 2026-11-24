<script lang="ts">
	import { vulnSeverityLabel, vulnSeverityTone, type VulnSeverity } from '#lib/vulns.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** A severity badge, with the CVSS score and a KEV marker beside it. */
	let { severity, cvss = null, kev = false }: { severity: VulnSeverity; cvss?: number | null; kev?: boolean } = $props();
</script>

<span class="inline-flex flex-wrap items-center gap-1.5 whitespace-nowrap">
	<Badge tone={vulnSeverityTone[severity]}>{vulnSeverityLabel[severity]}{cvss != null ? ` ${cvss.toFixed(1)}` : ''}</Badge>
	{#if kev}<Badge tone="danger" title="In CISA's catalog of known exploited vulnerabilities">Exploited</Badge>{/if}
</span>
