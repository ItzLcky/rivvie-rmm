import type { Component } from 'svelte';
import { Building2, FileCode2, History, LayoutDashboard, ListChecks, Monitor, Settings } from '@lucide/svelte';
import type { Role } from '#lib/types.js';

export interface NavItem {
	href: string;
	label: string;
	icon: Component<{ class?: string }>;
	/** Minimum role. */
	role?: Role;
	/** `g <key>` jumps here. */
	key?: string;
	/** Keeps the client switcher's ?client= when followed. */
	scoped?: boolean;
}
export interface NavGroup {
	label: string;
	items: NavItem[];
}

/** The sidebar. Later phases add Schedules and Patches (Automation), Alerts and Service desk. */
export const nav: NavGroup[] = [
	{ label: 'Overview', items: [{ href: '/', label: 'Dashboard', icon: LayoutDashboard, key: 'd', scoped: true }] },
	{
		label: 'Devices',
		items: [
			{ href: '/agents', label: 'Agents', icon: Monitor, key: 'a', scoped: true },
			{ href: '/clients', label: 'Clients & Sites', icon: Building2, key: 'c', scoped: true }
		]
	},
	{
		label: 'Automation',
		items: [
			{ href: '/scripts', label: 'Scripts', icon: FileCode2, key: 's', scoped: true },
			{ href: '/jobs', label: 'Jobs', icon: ListChecks, key: 'j', scoped: true }
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
