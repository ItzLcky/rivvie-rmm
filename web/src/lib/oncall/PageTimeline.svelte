<script lang="ts">
	import { Check, PhoneCall } from '@lucide/svelte';
	import { api, qs } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { OncallPage, PageDelivery } from '#lib/types.js';
	import Badge, { type Tone } from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';

	/** The pages of an alert (or ticket), with who was reached how: the paging timeline. */
	let { alertId, ticketId, version = 0 }: { alertId?: string; ticketId?: string; version?: number } = $props();

	let pages = $state<OncallPage[]>([]);
	function load() {
		api.get<OncallPage[]>(`/oncall/pages${qs({ alert_id: alertId, ticket_id: ticketId })}`).then((p) => (pages = p)).catch(() => (pages = []));
	}
	$effect(() => {
		void version;
		load();
	});

	const status: Record<OncallPage['status'], [string, Tone]> = {
		held: ['Held (business hours)', 'neutral'],
		triggered: ['Paging', 'danger'],
		acknowledged: ['Acknowledged', 'success'],
		resolved: ['Resolved', 'neutral']
	};
	const methods: Record<PageDelivery['method'], string> = { sms: 'Text message', email: 'Email', push: 'Push', channel: 'Channel' };
	const tone = (d: PageDelivery): Tone => (d.status === 'sent' ? 'success' : d.status === 'failed' ? 'danger' : d.status === 'cancelled' ? 'neutral' : 'warning');
	async function ack(p: OncallPage) {
		if (await attempt(() => api.post(`/oncall/pages/${p.id}/ack`), 'Page acknowledged.')) load();
	}
</script>

{#if pages.length}
	<section class="card" aria-label="Paging">
		<header class="border-border flex min-h-12 items-center gap-2 border-b px-4 py-3">
			<PhoneCall class="text-muted size-4" aria-hidden="true" />
			<h2 class="panel-title">Paging</h2>
		</header>
		{#each pages as p (p.id)}
			<div class="border-border border-b px-4 py-3 last:border-b-0">
				<div class="flex flex-wrap items-center gap-2 text-sm">
					<Badge tone={status[p.status][1]} dot={p.status === 'triggered'}>{status[p.status][0]}</Badge>
					<span class="font-medium">{p.policy_name ?? 'Deleted policy'}</span>
					<span class="text-muted text-xs">step {p.step + 1}{p.round ? `, repeat ${p.round}` : ''}</span>
					{#if (p.status === 'triggered' || p.status === 'held') && can('technician')}
						<Button size="sm" icon={Check} class="ml-auto" onclick={() => ack(p)}>Acknowledge page</Button>
					{/if}
				</div>
				<ol class="border-border mt-3 ml-1.5 space-y-2 border-l pl-4 text-sm">
					<li><span class="text-muted text-xs" title={datetime(p.created_at)}>{ago(p.created_at)}</span> Page opened</li>
					{#each p.deliveries as d (d.id)}
						<li class="flex flex-wrap items-center gap-x-2 gap-y-1">
							<span class="text-muted text-xs" title={datetime(d.sent_at ?? d.created_at)}>{ago(d.sent_at ?? d.created_at)}</span>
							<span>Step {d.step + 1}: {methods[d.method]} to <span class="font-medium">{d.user_name ?? d.channel_name ?? 'someone'}</span></span>
							<Badge tone={tone(d)}>{d.status === 'pending' ? (d.attempts ? `Retrying (${d.attempts})` : 'Scheduled') : d.status === 'sent' ? 'Sent' : d.status === 'failed' ? 'Failed' : 'Not needed'}</Badge>
							{#if d.error && d.status !== 'sent'}<span class="text-danger w-full text-xs break-words">{d.error}</span>{/if}
						</li>
					{/each}
					{#if p.acked_at}<li><span class="text-muted text-xs" title={datetime(p.acked_at)}>{ago(p.acked_at)}</span> Acknowledged{p.acked_by_name ? ` by ${p.acked_by_name}` : ''}</li>{/if}
					{#if p.resolved_at}<li><span class="text-muted text-xs" title={datetime(p.resolved_at)}>{ago(p.resolved_at)}</span> Resolved</li>{/if}
					{#if p.status === 'triggered' && p.next_escalation_at}<li class="text-muted text-xs">Escalates at {datetime(p.next_escalation_at)} unless acknowledged</li>{/if}
				</ol>
			</div>
		{/each}
	</section>
{/if}
