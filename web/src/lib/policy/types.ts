/** Policy management (docs/design/policies.md, docs/design/policies-api.md). */

export type Module = 'alert' | 'schedule' | 'patch' | 'security' | 'remote_access' | 'agent' | 'software';
export type Platform = 'workstation' | 'server';
/** Why a device uses its set. */
export type Reason = 'pin' | 'site' | 'client' | 'default';
export type Config = Record<string, unknown>;

/** A policy set as listed (`GET /policy-sets`). */
export interface SetRow {
	id: string; parent_id: string | null; client_id: string | null; client_name: string | null;
	name: string; description: string; builtin: boolean;
	/** All devices is 0. */
	depth: number;
	/** Devices using it (of the clients the user can see). */
	devices: number;
	/** Items defined here, overrides held here. */
	items: number; overrides: number;
	defines: Module[]; overrides_modules: Module[];
	/** Categories whose default set it is. */
	default_for: string[];
	created_at: string; updated_at: string;
}

/** A set's place in the tree; chains run from All devices down. */
export interface ChainEntry { id: string; name: string; client_id: string | null; builtin: boolean }

/** One item as it applies in one set. */
export interface ItemView {
	id: string; module: Module; name: string;
	origin_set_id: string; origin_set_name: string;
	/** Relative to the set being viewed. */
	status: 'defined' | 'inherited' | 'overridden';
	/** Merged, as it applies in this set. */
	enabled: boolean; config: Config;
	/** As defined at the origin. */
	item_enabled: boolean; item_config: Config;
	/** The set each leaf field's value comes from, by dotted path (`params.threshold`), plus `enabled`. */
	sources: Record<string, string>;
	/** This set's override (sparse). */
	override: { enabled: boolean | null; config: Config; updated_at: string } | null;
	limit: { client_id: string | null; client_name: string | null; site_id: string | null; site_name: string | null; excluded: { id: string; hostname: string }[] };
	/** May edit the item at its origin; may override it in the set being viewed. */
	editable: boolean; overridable: boolean;
	open_alerts: number;
	schedule: { next_run_at: string | null; last_run_at: string | null } | null;
	/** Agent view only. */
	applies?: boolean; excluded?: boolean;
}

export interface SetDetail extends SetRow {
	chain: ChainEntry[];
	children: SetRow[];
	policies: ItemView[];
	/** May rename, move, delete it and add items to it. */
	editable: boolean;
}

export interface SetAgent {
	id: string; hostname: string; online: boolean; os_family: 'linux' | 'windows' | 'macos' | 'other'; platform: Platform;
	client_id: string; client_name: string; site_id: string; site_name: string; category_id: string; category_name: string; reason: Reason;
}

export interface Category {
	id: string; name: string; description: string; builtin: boolean;
	os_family: 'windows' | 'linux' | 'macos' | null; platform: Platform | null;
	default_set_id: string; default_set_name: string; devices: number; created_at: string; updated_at: string;
}

export interface Assignment {
	id: string; client_id: string; client_name: string; site_id: string | null; site_name: string | null;
	category_id: string; category_name: string; policy_set_id: string; policy_set_name: string; updated_at: string;
}

export interface AgentPolicy {
	agent_id: string; hostname: string; client_id: string; site_id: string; platform: Platform;
	category: { id: string; name: string; builtin: boolean; manual: boolean };
	set: ChainEntry; reason: Reason; assignment_id: string | null; pin: ChainEntry | null;
	chain: ChainEntry[]; policies: ItemView[];
}
