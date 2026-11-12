import { goto } from '$app/navigation';

/** An API error: the HTTP status, the server's message and the whole error body. */
export class PortalError extends Error {
	constructor(
		public status: number,
		message: string,
		public data: { error?: string; mfa_required?: boolean } | null = null
	) {
		super(message);
	}
}

/**
 * Calls the API under `/api` for client-portal pages. Unlike the technician wrapper, a 401
 * sends the user to the portal's own sign-in page, never to the technician one.
 */
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const form = body instanceof FormData;
	const res = await fetch(`/api${path}`, {
		method,
		credentials: 'same-origin',
		// FormData sets its own multipart content type (with the boundary).
		headers: body !== undefined && !form ? { 'content-type': 'application/json' } : undefined,
		body: body === undefined ? undefined : form ? body : JSON.stringify(body)
	});
	const data = res.headers.get('content-type')?.includes('json') ? await res.json().catch(() => null) : null;
	if (res.status === 401 && path.startsWith('/portal/') && !path.startsWith('/portal/auth/') && location.pathname !== '/portal/login') {
		const here = location.pathname + location.search;
		await goto(here === '/portal' ? '/portal/login' : `/portal/login?next=${encodeURIComponent(here)}`, { replace: true });
	}
	if (!res.ok) throw new PortalError(res.status, data?.error ?? (res.status === 401 ? 'Please sign in again' : res.statusText || 'Request failed'), data);
	return data as T;
}

/** Paths are relative to `/api/portal`. */
export const portal = {
	get: <T>(p: string) => request<T>('GET', `/portal${p}`),
	post: <T>(p: string, b: unknown = {}) => request<T>('POST', `/portal${p}`, b),
	/** Multipart upload; the browser sets the content type. */
	form: <T>(p: string, f: FormData) => request<T>('POST', `/portal${p}`, f)
};

/** The public satisfaction survey (no session: the token in the URL is the key). */
export const survey = {
	get: <T>(token: string) => request<T>('GET', `/feedback/${encodeURIComponent(token)}`),
	answer: (token: string, rating: 'good' | 'bad', comment = '') =>
		request<{ ok: boolean }>('POST', `/feedback/${encodeURIComponent(token)}`, { rating, comment })
};

/** Link to download a ticket attachment (the portal cookie is sent with it). */
export const attachmentUrl = (ticket: string, attachment: string) => `/api/portal/tickets/${ticket}/attachments/${attachment}`;

export function qs(params: Record<string, string | undefined | null>): string {
	const u = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) if (v) u.set(k, v);
	const s = u.toString();
	return s ? `?${s}` : '';
}

/** A `next` value that stays inside the portal. */
export function safeNext(next: string | null): string {
	return next && (next === '/portal' || next.startsWith('/portal/')) && !next.startsWith('/portal/login') ? next : '/portal';
}
