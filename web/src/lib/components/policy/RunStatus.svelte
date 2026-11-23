<script lang="ts">
	import { CheckCircle2, Clock, Hourglass, Loader, MinusCircle, XCircle } from '@lucide/svelte';
	import { runReason, runStatusLabels, type RunStatus } from '#lib/policy/policy.js';
	import Badge, { type Tone } from '#lib/ui/Badge.svelte';

	/** One run's state, with why when it isn't the plain outcome. Icon and text, never colour alone. */
	let { status, reason = null }: { status: RunStatus; reason?: string | null } = $props();
	const tones: Record<RunStatus, { tone: Tone; icon: typeof Clock }> = {
		waiting: { tone: 'warning', icon: Hourglass },
		pending: { tone: 'info', icon: Loader },
		succeeded: { tone: 'success', icon: CheckCircle2 },
		failed: { tone: 'danger', icon: XCircle },
		skipped: { tone: 'neutral', icon: MinusCircle }
	};
	const t = $derived(tones[status]);
</script>

<Badge tone={t.tone} icon={t.icon} title={reason ? runReason(reason) : undefined}>{runStatusLabels[status]}</Badge>
