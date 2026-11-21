/** Types for time, scheduling, projects, client docs and reports (see api/time.rs, api/pm.rs, api/reports.rs). */

export type WeekStatus = 'open' | 'submitted' | 'approved' | 'rejected';

export interface TimeEntry {
	id: string;
	user_id: string;
	user_name: string;
	client_id: string | null;
	client_name: string | null;
	ticket_id: string | null;
	ticket_number: number | null;
	ticket_subject: string | null;
	project_id: string | null;
	project_name: string | null;
	work_type_id: string;
	work_type_name: string;
	started_at: string;
	/** Null while the timer runs. */
	ended_at: string | null;
	minutes: number | null;
	billable: boolean;
	note: string;
	coverage: string | null;
	contract_name: string | null;
	/** Null without billing.read. */
	rate: number | null;
	amount: number | null;
	invoiced: boolean;
	week_start: string;
	week_status: WeekStatus;
}

export interface Timesheet {
	id: string | null;
	user_id: string;
	user_name: string;
	week_start: string;
	status: WeekStatus;
	submitted_at: string | null;
	decided_by_name: string | null;
	decided_at: string | null;
	note: string;
	minutes: number;
	billable_minutes: number;
}

export interface Week {
	timesheet: Timesheet;
	entries: TimeEntry[];
}

export interface WorkType {
	id: string;
	name: string;
	rate: number | null;
	billable: boolean;
	active: boolean;
	position: number;
}

export interface Product {
	id: string;
	sku: string | null;
	name: string;
	description: string;
	kind: string;
	cost: number | null;
	price: number | null;
	active: boolean;
}

export interface Charge {
	id: string;
	client_id: string;
	client_name: string;
	ticket_id: string | null;
	ticket_number: number | null;
	product_id: string | null;
	description: string;
	/** Quantity × 1000. */
	quantity_milli: number;
	unit_price: number | null;
	unit_cost: number | null;
	day: string;
	invoiced: boolean;
	created_by_name: string | null;
}

export interface BillingSettings {
	currency: string;
	company_address: string;
	invoice_prefix: string;
	invoice_terms_days: number;
	invoice_footer: string;
	default_rate: number;
	next_number: string;
}

export interface ScheduleEntry {
	id: string;
	user_id: string;
	user_name: string;
	starts_at: string;
	ends_at: string;
	title: string;
	ticket_id: string | null;
	ticket_number: number | null;
	ticket_subject: string | null;
	project_id: string | null;
	project_name: string | null;
	client_name: string | null;
	notes: string;
}

export type ProjectStatus = 'planned' | 'active' | 'on_hold' | 'done' | 'cancelled';

export interface Project {
	id: string;
	client_id: string;
	client_name: string;
	name: string;
	description: string;
	status: ProjectStatus;
	budget_minutes: number;
	start_date: string | null;
	due_date: string | null;
	owner_id: string | null;
	owner_name: string | null;
	contract_id: string | null;
	logged_minutes: number;
	estimate_minutes: number;
	tasks: number;
	tasks_done: number;
	created_at: string;
}

export type TaskStatus = 'todo' | 'doing' | 'done';

export interface ProjectTask {
	id: string;
	phase: string;
	title: string;
	status: TaskStatus;
	estimate_minutes: number;
	assignee_id: string | null;
	assignee_name: string | null;
	ticket_id: string | null;
	ticket_number: number | null;
	ticket_status: string | null;
	due_date: string | null;
	position: number;
	logged_minutes: number;
}

export interface ProjectDetail extends Project {
	task_list: ProjectTask[];
	burn: { week: string; minutes: number }[];
}

export interface Breakdown {
	name: string;
	opened: number;
	closed: number;
}

export interface Attainment {
	met: number;
	total: number;
	pct: number | null;
}

export interface ServiceDeskReport {
	from: string;
	to: string;
	opened: number;
	closed: number;
	backlog: number;
	backlog_age: { under_1d: number; '1_3d': number; '3_7d': number; '7_30d': number; over_30d: number };
	first_response_median_mins: number | null;
	resolution_median_mins: number | null;
	sla: { respond: Attainment; resolve: Attainment };
	csat: { good: number; bad: number; pct: number | null };
	by_client: Breakdown[];
	by_board: Breakdown[];
	by_technician: Breakdown[];
	by_type: Breakdown[];
}

export interface UtilisationRow {
	user_id: string;
	name: string;
	logged_minutes: number;
	billable_minutes: number;
	charged_minutes: number;
	available_minutes: number;
	utilisation_pct: number | null;
	billable_pct: number | null;
}

export interface UtilisationReport {
	from: string;
	to: string;
	technicians: UtilisationRow[];
}

export interface ProfitRow {
	client_id: string;
	name: string;
	currency: string;
	revenue: number;
	minutes: number;
	time_cost: number;
	product_cost: number;
	margin: number;
	margin_pct: number | null;
}

export interface ProfitabilityReport {
	from: string;
	to: string;
	clients: ProfitRow[];
}

/** A ticket as the pickers need it (from GET /tickets). */
export interface TicketRef {
	id: string;
	number: number;
	subject: string;
	client_id: string | null;
	client_name: string | null;
}
