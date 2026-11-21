/** What a rendered page needs from around it (docs/design/documentation.md): shared by the Docs tab and the ticket page's drawer. */
import { api } from '#lib/api.js';
import type { AgentSummary, Page } from '#lib/types.js';
import type { DocContext } from './blocks.js';
import type { DocDetail } from './types.js';

/** The client's devices for `device` blocks, fetched once on first use (and again after a failure). */
export function agentLoader(clientId: string): () => Promise<Map<string, AgentSummary>> {
	let list: Promise<Map<string, AgentSummary>> | null = null;
	return () =>
		(list ??= api
			.get<Page<AgentSummary>>(`/agents?client_id=${clientId}&limit=500`)
			.then((p) => new Map(p.items.map((a) => [a.id, a])))
			.catch((e) => {
				list = null;
				throw e;
			}));
}

export const docContext = (d: DocDetail, agents: DocContext['agents'], extra: Partial<DocContext> = {}): DocContext => ({
	clientId: d.client_id,
	credentials: new Map(d.credentials.map((c) => [c.id, c])),
	credentialsHidden: d.credentials_hidden,
	agents,
	...extra
});

/** The linked credentials as chips (`[name](vault:id)`), for the strip under a page's header. */
export const chipSource = (d: DocDetail) => d.credentials.map((c) => `[${c.name.replace(/[[\]\\]/g, '\\$&')}](vault:${c.id})`).join(' ');

/** The page on its client's Docs tab. */
export const docPageHref = (clientId: string, docId: string) => `/clients/${clientId}?tab=docs&doc=${encodeURIComponent(docId)}`;
