import { goto } from '$app/navigation';

export class ApiError extends Error {
	constructor(public status: number, message: string) {
		super(message);
	}
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(`/api${path}`, {
		method,
		credentials: 'same-origin',
		headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});
	if (res.status === 401 && !path.startsWith('/auth/')) {
		await goto(`/login?next=${encodeURIComponent(location.pathname)}`);
	}
	const data = res.headers.get('content-type')?.includes('json') ? await res.json() : null;
	if (!res.ok) throw new ApiError(res.status, data?.error ?? res.statusText);
	return data as T;
}

export const api = {
	get: <T>(p: string) => request<T>('GET', p),
	post: <T>(p: string, b: unknown = {}) => request<T>('POST', p, b),
	put: <T>(p: string, b: unknown) => request<T>('PUT', p, b),
	del: <T>(p: string) => request<T>('DELETE', p)
};

export function qs(params: Record<string, string | boolean | undefined | null>): string {
	const u = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v));
	const s = u.toString();
	return s ? `?${s}` : '';
}
