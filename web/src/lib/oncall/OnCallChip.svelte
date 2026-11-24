<script lang="ts">
	import { PhoneCall } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';
	import type { OnCallNow } from '#lib/types.js';

	/** Who is on call now, per schedule: a chip per schedule, nothing when there are none. */
	let list = $state<OnCallNow[]>([]);
	$effect(() => {
		api.get<OnCallNow[]>('/oncall/now').then((l) => (list = l)).catch(() => (list = []));
	});
	const until = (s: OnCallNow) => (s.until ? ` until ${datetime(s.until)}` : '');
</script>

{#if list.length}
	<ul class="flex flex-wrap items-center gap-2" aria-label="On call now">
		{#each list as s (s.schedule_id)}
			<li>
				<a
					href="/settings/oncall?schedule={s.schedule_id}"
					class="border-border bg-surface hover:bg-hover inline-flex h-7 max-w-full items-center gap-1.5 rounded-full border px-2.5 text-xs"
					title="{s.schedule_name}: {s.user_name ?? 'nobody'}{until(s)}"
				>
					<PhoneCall class="text-accent size-3.5 shrink-0" aria-hidden="true" />
					<span class="text-muted">{s.schedule_name}:</span>
					<span class="truncate font-medium">{s.user_name ?? 'Nobody on call'}</span>
				</a>
			</li>
		{/each}
	</ul>
{/if}
