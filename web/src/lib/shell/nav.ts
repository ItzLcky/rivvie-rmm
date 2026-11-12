import type { Component } from 'svelte';
import { BarChart3, BellRing, BookOpen, CalendarDays, Clock, FileSignature, FolderKanban, Receipt, Building2, LifeBuoy, CalendarClock, FileCode2, History, LayoutDashboard, ListChecks, Monitor, PackageCheck, Settings, Shield, ShieldCheck } from '@lucide/svelte';
import type { Role } from '#lib/types.js';
import type { Permission } from '#lib/session.svelte.js';

export interface NavItem {
	href: string;
	label: string;
	icon: Component<{ class?: string }>;
	/** Minimum role. */
	role?: Role;
	/** A named permission it needs (billing pages). */
	perm?: Permission;
	/** `g <key>` jumps here. */
	key?: string;
	/** Keeps the client switcher's ?client= when followed. */
	scoped?: boolean;
	/** Shows the open alert count, or unassigned open tickets. */
	badge?: 'alerts' | 'tickets';
}
export interface NavGroup {
	label: string;
	items: NavItem[];
}

/** The sidebar. */
export const nav: NavGroup[] = [
	{ label: 'Overview', items: [{ href: '/', label: 'Dashboard', icon: LayoutDashboard, key: 'd', scoped: true }] },
	{
		label: 'Service desk',
		items: [
			{ href: '/tickets', label: 'Tickets', icon: LifeBuoy, key: 't', scoped: true, badge: 'tickets' },
			{ href: '/schedule', label: 'Schedule', icon: CalendarDays, key: 'w', role: 'technician' },
			{ href: '/projects', label: 'Projects', icon: FolderKanban, key: 'o', scoped: true },
			{ href: '/kb', label: 'Knowledge base', icon: BookOpen, key: 'k' }
		]
	},
	{
		label: 'Business',
		items: [
			{ href: '/time', label: 'Time', icon: Clock, key: 'i', role: 'technician' },
			{ href: '/billing', label: 'Billing', icon: Receipt, key: 'b', perm: 'billing.read', scoped: true },
			{ href: '/contracts', label: 'Contracts', icon: FileSignature, key: 'n', perm: 'billing.read', scoped: true },
			{ href: '/reports', label: 'Reports', icon: BarChart3, key: 'r' }
		]
	},
	{
		label: 'Devices',
		items: [
			{ href: '/agents', label: 'Agents', icon: Monitor, key: 'a', scoped: true },
			{ href: '/clients', label: 'Clients & Sites', icon: Building2, key: 'c', scoped: true }
		]
	},
	{
		label: 'Monitoring',
		items: [
			{ href: '/alerts', label: 'Alerts', icon: BellRing, key: 'e', scoped: true, badge: 'alerts' },
			{ href: '/security', label: 'Security', icon: Shield, key: 'v', scoped: true },
			{ href: '/policies', label: 'Alert policies', icon: ShieldCheck, key: 'p', scoped: true }
		]
	},
	{
		label: 'Automation',
		items: [
			{ href: '/scripts', label: 'Scripts', icon: FileCode2, key: 's', scoped: true },
			{ href: '/schedules', label: 'Schedules', icon: CalendarClock, key: 'h', scoped: true },
			{ href: '/jobs', label: 'Jobs', icon: ListChecks, key: 'j', scoped: true },
			{ href: '/patches', label: 'Patches', icon: PackageCheck, key: 'u', scoped: true }
		]
	},
	{
		label: 'Admin',
		items: [
			{ href: '/audit', label: 'Audit log', icon: History, role: 'admin', key: 'l' },
			{ href: '/settings', label: 'Company settings', icon: Settings, role: 'admin', key: ',' }
		]
	}
];

export function isActive(href: string, path: string): boolean {
	return href === '/' ? path === '/' : path === href || path.startsWith(`${href}/`);
}
