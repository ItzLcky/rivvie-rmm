import type { Tone } from '#lib/ui/Badge.svelte';
import type { BillingCycle, Contract, ContractKind, DeviceFilter, Invoice, InvoiceFilter, LineKind } from './types';

export const contractKinds: { value: ContractKind; label: string; hint: string }[] = [
	{ value: 'per_device', label: 'Per device', hint: 'A price per enrolled agent each cycle.' },
	{ value: 'per_user', label: 'Per user', hint: 'A price per user, for a user count you keep up to date.' },
	{ value: 'block_hours', label: 'Block hours', hint: 'A bank of hours bought each cycle; time draws it down and the rest bills at the overage rate.' },
	{ value: 'recurring', label: 'Recurring', hint: 'A flat fee plus fixed items (licences, services) each cycle.' },
	{ value: 'time_materials', label: 'Time & materials', hint: 'Nothing recurring; covered work types bill at this contract’s rates.' }
];
export const kindLabel = (k: ContractKind) => contractKinds.find((x) => x.value === k)?.label ?? k;

export const cycles: { value: BillingCycle; label: string }[] = [
	{ value: 'monthly', label: 'Monthly' },
	{ value: 'quarterly', label: 'Quarterly' },
	{ value: 'annual', label: 'Annual' }
];
export const cycleLabel = (c: BillingCycle) => cycles.find((x) => x.value === c)?.label ?? c;
export const perCycle = (c: BillingCycle) => ({ monthly: 'month', quarterly: 'quarter', annual: 'year' })[c] ?? c;

export const deviceFilters: { value: DeviceFilter; label: string }[] = [
	{ value: 'all', label: 'All devices' },
	{ value: 'workstations', label: 'Workstations only' },
	{ value: 'servers', label: 'Servers only' }
];

export const invoiceFilters: { value: InvoiceFilter | 'all'; label: string }[] = [
	{ value: 'all', label: 'All' },
	{ value: 'draft', label: 'Drafts' },
	{ value: 'unpaid', label: 'Unpaid' },
	{ value: 'overdue', label: 'Overdue' },
	{ value: 'paid', label: 'Paid' },
	{ value: 'void', label: 'Void' }
];

export const statusLabels: Record<Invoice['status'], string> = { draft: 'Draft', finalised: 'Finalised', sent: 'Sent', paid: 'Paid', void: 'Void' };
export const statusTones: Record<Invoice['status'], Tone> = { draft: 'neutral', finalised: 'info', sent: 'accent', paid: 'success', void: 'neutral' };

export const lineKindLabels: Record<LineKind, string> = {
	recurring: 'Recurring', devices: 'Devices', users: 'Users', block: 'Block hours', overage: 'Overage', time: 'Time', product: 'Product', manual: 'Manual'
};

export function invoiceTitle(i: Pick<Invoice, 'number' | 'kind'>): string {
	return i.number ?? (i.kind === 'credit_note' ? 'Draft credit note' : 'Draft invoice');
}

/** "1 Oct 2026" from an ISO date (no time zone shift). */
export function day(iso: string | null | undefined): string {
	if (!iso) return '–';
	const [y, m, d] = iso.slice(0, 10).split('-').map(Number);
	return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

export function period(a: string | null | undefined, b: string | null | undefined): string {
	return a && b ? `${day(a)} – ${day(b)}` : a ? `from ${day(a)}` : '–';
}

const pad = (n: number) => String(n).padStart(2, '0');
export const isoDay = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
export const today = () => isoDay(new Date());

/** The calendar month before today: [first, last]. */
export function lastMonth(now = new Date()): [string, string] {
	const first = new Date(now.getFullYear(), now.getMonth() - 1, 1);
	const last = new Date(now.getFullYear(), now.getMonth(), 0);
	return [isoDay(first), isoDay(last)];
}

/** Ended, not started yet, or running. */
export function contractState(c: Pick<Contract, 'active' | 'start_date' | 'end_date'>): { label: string; tone: Tone } {
	if (c.active) return { label: 'Active', tone: 'success' };
	return c.start_date > today() ? { label: 'Not started', tone: 'info' } : { label: 'Ended', tone: 'neutral' };
}

/** Block balance tone: danger when exhausted, warning under the low-balance mark. */
export function balanceTone(c: Pick<Contract, 'balance_minutes' | 'low_balance_minutes'>): Tone {
	const b = c.balance_minutes ?? 0;
	if (b <= 0) return 'danger';
	if (c.low_balance_minutes && b <= c.low_balance_minutes) return 'warning';
	return 'neutral';
}
