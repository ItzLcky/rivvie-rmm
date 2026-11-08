export type ToastTone = 'success' | 'error' | 'info';
export interface Toast {
	id: number;
	tone: ToastTone;
	message: string;
	action?: { label: string; run: () => void };
	href?: { label: string; href: string };
}

export const toasts = $state<Toast[]>([]);
let next = 1;
const timers = new Map<number, ReturnType<typeof setTimeout>>();

export function dismiss(id: number) {
	clearTimeout(timers.get(id));
	timers.delete(id);
	const i = toasts.findIndex((t) => t.id === id);
	if (i >= 0) toasts.splice(i, 1);
}

function push(tone: ToastTone, message: string, extra: Partial<Pick<Toast, 'action' | 'href'>> = {}, ms?: number) {
	const id = next++;
	toasts.push({ id, tone, message, ...extra });
	if (toasts.length > 4) dismiss(toasts[0].id);
	schedule(id, ms ?? (tone === 'error' ? 9000 : extra.action ? 8000 : 5000));
	return id;
}

export function schedule(id: number, ms: number) {
	clearTimeout(timers.get(id));
	timers.set(id, setTimeout(() => dismiss(id), ms));
}
export function hold(id: number) {
	clearTimeout(timers.get(id));
}

export const toast = {
	success: (m: string, extra?: Partial<Pick<Toast, 'action' | 'href'>>) => push('success', m, extra),
	info: (m: string, extra?: Partial<Pick<Toast, 'action' | 'href'>>) => push('info', m, extra),
	error: (m: string | unknown, extra?: Partial<Pick<Toast, 'action' | 'href'>>) =>
		push('error', typeof m === 'string' ? m : m instanceof Error ? m.message : String(m), extra)
};

/** Runs an action, toasting its failure (and success message, if given). Returns whether it worked. */
export async function attempt(fn: () => Promise<unknown>, success?: string): Promise<boolean> {
	try {
		await fn();
		if (success) toast.success(success);
		return true;
	} catch (e) {
		toast.error(e);
		return false;
	}
}
