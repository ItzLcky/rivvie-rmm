/** Billing API shapes (crates/rmm-server/src/api/billing.rs). Money is integer minor units. */

export interface WorkType {
	id: string;
	name: string;
	/** Per hour; null falls through to the work role / technician rate (or hidden without billing.read). */
	rate: number | null;
	billable: boolean;
	active: boolean;
	position: number;
}

export interface WorkRole {
	id: string;
	name: string;
	rate: number;
	users: number;
}

export interface UserRates {
	id: string;
	name: string;
	email: string;
	role: string;
	work_role_id: string | null;
	default_rate: number | null;
	cost_rate: number;
	capacity_hours: number;
}

export type ProductKind = 'one_off' | 'recurring';
export interface Product {
	id: string;
	sku: string | null;
	name: string;
	description: string;
	kind: ProductKind;
	cost: number | null;
	price: number | null;
	active: boolean;
}

export type ContractKind = 'per_device' | 'per_user' | 'block_hours' | 'time_materials' | 'recurring';
export type BillingCycle = 'monthly' | 'quarterly' | 'annual';
export type DeviceFilter = 'all' | 'workstations' | 'servers';

export interface Contract {
	id: string;
	client_id: string;
	client_name: string;
	name: string;
	kind: ContractKind;
	start_date: string;
	end_date: string | null;
	billing_cycle: BillingCycle;
	unit_price: number;
	device_filter: DeviceFilter;
	user_count: number;
	block_minutes: number;
	overage_rate: number | null;
	low_balance_minutes: number;
	covered_work_type_ids: string[];
	sla_policy_id: string | null;
	sla_policy_name: string | null;
	manager_id: string | null;
	notes: string;
	active: boolean;
	/** Block hours: minutes left in the bank. */
	balance_minutes: number | null;
	/** Agents the client has enrolled now. */
	devices: number;
	created_at: string;
}

export interface ContractItem {
	id?: string;
	product_id: string | null;
	description: string;
	quantity_milli: number;
	unit_price: number;
}

export interface BankEntry {
	id: number;
	minutes: number;
	reason: 'purchase' | 'usage' | 'adjustment';
	note: string;
	ticket_number: number | null;
	invoice_number: string | null;
	created_at: string;
}

export interface ContractDetail extends Contract {
	items: ContractItem[];
	rate_overrides: { work_type_id: string; rate: number }[];
	bank: BankEntry[];
}

/** The body of POST/PUT /contracts. */
export interface ContractInput {
	client_id: string;
	name: string;
	kind: ContractKind;
	start_date: string;
	end_date: string | null;
	billing_cycle: BillingCycle;
	unit_price: number;
	device_filter: DeviceFilter;
	user_count: number;
	block_minutes: number;
	overage_rate: number | null;
	low_balance_minutes: number;
	covered_work_type_ids: string[];
	sla_policy_id: string | null;
	manager_id: string | null;
	notes: string;
	items: Omit<ContractItem, 'id'>[];
	rate_overrides: { work_type_id: string; rate: number }[];
}

export type InvoiceStatus = 'draft' | 'finalised' | 'sent' | 'paid' | 'void';
export type InvoiceKind = 'invoice' | 'credit_note';
export type InvoiceFilter = InvoiceStatus | 'unpaid' | 'overdue';

/** Accounting sync state kept on the invoice. */
export interface InvoiceExternal {
	provider?: string;
	id?: string;
	synced_at?: string;
	error?: string | null;
}

export interface Invoice {
	id: string;
	number: string | null;
	client_id: string;
	client_name: string;
	kind: InvoiceKind;
	credit_of: string | null;
	credit_of_number: string | null;
	currency: string;
	status: InvoiceStatus;
	issue_date: string;
	due_date: string;
	period_start: string | null;
	period_end: string | null;
	total: number;
	notes: string;
	bill_to: string;
	finalised_at: string | null;
	sent_at: string | null;
	paid_at: string | null;
	voided_at: string | null;
	external: InvoiceExternal;
	overdue: boolean;
	created_at: string;
}

export type LineKind = 'recurring' | 'devices' | 'users' | 'block' | 'overage' | 'time' | 'product' | 'manual';
export interface InvoiceLine {
	id: string;
	position: number;
	kind: LineKind;
	description: string;
	quantity_milli: number;
	unit_price: number;
	amount: number;
	contract_id: string | null;
	product_id: string | null;
	details: Record<string, unknown>;
}

export interface InvoiceDetail extends Invoice {
	lines: InvoiceLine[];
	/** Default recipients: the client's billing contacts (or primary contact). */
	recipients: string[];
}

export interface BillingSettings {
	currency: string;
	company_address: string;
	invoice_prefix: string;
	invoice_terms_days: number;
	invoice_footer: string;
	default_rate: number;
	/** Read-only: the number the next finalised invoice gets. */
	next_number?: string;
}

export interface ClientBilling {
	/** null: the company currency. */
	currency: string | null;
	billing_address: string;
	accounting_ids: Record<string, string>;
}

export type AccountingProvider = 'qbo' | 'xero';
export interface AccountingConnection {
	provider: AccountingProvider;
	label: string;
	redirect_uri: string;
	client_id: string;
	has_secret: boolean;
	connected: boolean;
	tenant_name: string | null;
	settings: { item_id?: string; account_code?: string; tax_type?: string };
	connected_at: string | null;
	last_sync_at: string | null;
	last_error: string | null;
}

export interface SyncResult {
	pushed: number;
	paid: number;
	errors: string[];
}

export interface BillingOverview {
	currencies: { currency: string; outstanding: number; overdue: number; drafts: number; outstanding_text: string; overdue_text: string }[];
	timesheets_pending: number;
}
