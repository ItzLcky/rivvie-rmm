import { api } from '#lib/api.js';
import { toast } from '#lib/toast.svelte.js';

/** What `POST /agents/{id}/wake` and `POST /agents/wake` report for each device. */
export type WakeOutcome = 'sent' | 'no_mac' | 'no_sender' | 'online';
export type WakeResult = { agent_id: string; outcome: WakeOutcome; sender_id?: string; error?: string };
export type WakeSummary = { results: WakeResult[]; sent: number; no_mac: number; no_sender: number; online: number; outcome?: WakeOutcome };

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** One line for a toast. */
export function wakeMessage(r: WakeSummary): string {
	const parts: string[] = [];
	if (r.sent) parts.push(`Wake-up sent to ${plural(r.sent, 'device')}`);
	if (r.online) parts.push(`${plural(r.online, 'device is', 'devices are')} online already`);
	if (r.no_mac) parts.push(`${plural(r.no_mac, 'device has', 'devices have')} no known network adapter`);
	if (r.no_sender) parts.push(`${plural(r.no_sender, 'device has', 'devices have')} no online agent at the site to send from`);
	return parts.join('; ') + '.';
}

/** Wakes devices and says how it went; resolves to the summary, or null on an error. */
export async function wake(ids: string[]): Promise<WakeSummary | null> {
	try {
		const r = ids.length === 1 ? await api.post<WakeSummary>(`/agents/${ids[0]}/wake`) : await api.post<WakeSummary>('/agents/wake', { agent_ids: ids });
		if (r.sent && !r.no_mac && !r.no_sender) toast.success(wakeMessage(r));
		else if (r.sent || r.online) toast.info(wakeMessage(r));
		else toast.error(wakeMessage(r));
		return r;
	} catch (e) {
		toast.error(e);
		return null;
	}
}
