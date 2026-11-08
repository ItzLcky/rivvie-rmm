<script lang="ts">
	import { CircleCheck, CircleDashed, CircleSlash, CircleX, Clock, LoaderCircle, TimerOff, Unplug } from '@lucide/svelte';
	import type { JobStatus } from '#lib/types.js';
	import Badge, { type Tone } from '#lib/ui/Badge.svelte';

	let { status }: { status: JobStatus } = $props();
	const map: Record<JobStatus, [Tone, string, typeof CircleCheck]> = {
		queued: ['neutral', 'Queued', Clock],
		sent: ['info', 'Running', LoaderCircle],
		succeeded: ['success', 'Succeeded', CircleCheck],
		failed: ['danger', 'Failed', CircleX],
		timed_out: ['warning', 'Timed out', TimerOff],
		error: ['danger', 'Error', CircleX],
		cancelled: ['neutral', 'Cancelled', CircleSlash],
		lost: ['warning', 'Lost', Unplug],
		expired: ['neutral', 'Expired', CircleDashed]
	};
	const [tone, label, icon] = $derived(map[status] ?? ['neutral', status, CircleDashed]);
</script>

<Badge {tone} {icon} class={status === 'sent' ? '[&_svg]:animate-spin' : ''}>{label}</Badge>
