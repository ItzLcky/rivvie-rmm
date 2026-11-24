/** Vulnerabilities (docs/design/vulnerabilities.md): types and labels shared by the pages. */
import type { Tone } from '#lib/ui/Badge.svelte';

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

export const vulnSeverityTone: Record<VulnSeverity, Tone> = { critical: 'danger', high: 'warning', medium: 'info', low: 'neutral', none: 'neutral', unknown: 'neutral' };
export const vulnSeverityLabel: Record<VulnSeverity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None', unknown: 'Unrated' };

export type Remediation =
	| { kind: 'patch'; update_id: string; title: string; version: string | null; approval: 'pending' | 'approved' | 'declined'; state: string }
	| { kind: 'upgrade'; package_id: string; package_name: string }
	| { kind: 'catalog'; product_id: string; product_name: string }
	| null;

export interface VulnRow {
	key: string; cve: string | null; advisories: string[]; summary: string; severity: VulnSeverity; cvss: number | null; epss: number | null; kev: boolean;
	published: string | null; devices: number; accepted_devices: number; fix_available: boolean; packages: string[]; first_seen: string;
}

export interface VulnSummary { critical: number; high: number; devices_affected: number; kev: number; unassessed: number; assessed: number; last_sync_at: string | null }

export interface VulnAdvisory {
	id: string; source: string; aliases: string[]; summary: string; details: string; severity: VulnSeverity; cvss: number | null; cvss_vector: string | null;
	published: string | null; modified: string | null; url: string | null;
}
export interface VulnRange { vuln_id: string; ecosystem: string; package: string; introduced: string | null; fixed: string | null; last_affected: string | null }
export interface VulnAcceptance {
	id: string; vuln_id: string; client_id: string; client_name: string; agent_id: string | null; hostname: string | null; note: string; expires_at: string | null;
	by_name: string | null; created_at: string; active: boolean;
}
export interface VulnDetail {
	key: string; cve: string | null; summary: string; severity: VulnSeverity; cvss: number | null; cvss_vector: string | null; epss: number | null; epss_percentile: number | null;
	kev: boolean; kev_added: string | null; kev_due: string | null; devices: number; accepted_devices: number;
	advisories: VulnAdvisory[]; ranges: VulnRange[]; acceptances: VulnAcceptance[];
}
export interface VulnDevice {
	agent_id: string; hostname: string; online: boolean; os_family: string; os_name: string; client_id: string; client_name: string; site_name: string;
	vuln_id: string; package: string; software_name: string; installed_version: string; fixed_version: string | null; fix_available: boolean; first_seen: string;
	accepted: boolean; product_id: string | null; remediation: Remediation;
}
export interface AgentFinding {
	key: string; cve: string | null; vuln_id: string; summary: string; severity: VulnSeverity; cvss: number | null; epss: number | null; kev: boolean;
	package: string; software_name: string; installed_version: string; fixed_version: string | null; fix_available: boolean; first_seen: string; accepted: boolean;
	remediation: Remediation;
}
export interface AgentVulns {
	ecosystem: string | null; unassessed: 'no_inventory' | 'old_agent' | 'unsupported_os' | null; evaluated_at: string | null; critical: number; high: number;
	findings: AgentFinding[];
}
export interface VulnSoftware {
	package: string; ecosystems: string[]; product_id: string | null; product_name: string | null; package_id: string | null; devices: number; cves: number;
	severity: VulnSeverity; kev: boolean; fix_available: boolean; fixed_versions: string[];
}
export interface Unassessed {
	devices: { agent_id: string; hostname: string; os_family: string; os_name: string; agent_version: string; client_name: string; reason: string }[];
	titles: { title: string; publisher: string | null; devices: number; versions: string[] }[];
	products: number;
}
export interface VulnFeed {
	name: string; label: string; enabled: boolean; needed: boolean; last_sync_at: string | null; last_attempt_at: string | null; progress: string | null; records: number; error: string | null;
}
export interface VulnFeeds { feeds: VulnFeed[]; running: boolean; nvd_api_key: boolean; automatic: boolean; attribution: string[] }
export interface VulnProduct {
	id: string; vendor: string; product: string; name: string; name_patterns: string[]; publisher_pattern: string | null; package_id: string | null; package_name: string | null;
	builtin: boolean; nvd_synced_at: string | null; devices: number;
}

export const unassessedLabel: Record<string, string> = {
	no_inventory: 'No inventory yet',
	old_agent: 'Update the agent',
	unsupported_os: 'Operating system not covered'
};

/** "12.3%" for an EPSS probability. */
export const epssPct = (v: number | null | undefined) => (v == null ? '–' : `${(v * 100).toFixed(v >= 0.1 ? 0 : 1)}%`);

/** Where a CVE is described upstream. */
export const cveUrl = (id: string) => (id.startsWith('CVE-') ? `https://www.cve.org/CVERecord?id=${id}` : null);
