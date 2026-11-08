/** Recently opened agents (this browser only), shown by the command palette before you type. */
export interface RecentAgent { id: string; hostname: string; client_name: string; os_family: string }

const KEY = 'rmm.recentAgents';

export function recentAgents(): RecentAgent[] {
	try {
		return JSON.parse(localStorage.getItem(KEY) ?? '[]');
	} catch {
		return [];
	}
}

export function rememberAgent(a: RecentAgent) {
	const list = [{ id: a.id, hostname: a.hostname, client_name: a.client_name, os_family: a.os_family }, ...recentAgents().filter((r) => r.id !== a.id)].slice(0, 6);
	try {
		localStorage.setItem(KEY, JSON.stringify(list));
	} catch {
		/* ignore */
	}
}

export function forgetAgent(id: string) {
	try {
		localStorage.setItem(KEY, JSON.stringify(recentAgents().filter((r) => r.id !== id)));
	} catch {
		/* ignore */
	}
}
