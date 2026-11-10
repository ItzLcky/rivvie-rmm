import { api } from '#lib/api.js';
import { confirmAction } from '#lib/confirm.svelte.js';
import { attempt } from '#lib/toast.svelte.js';

/** The last path segment (Windows or Unix). */
export function baseName(path: string): string {
	return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/** Deletes a quarantined file for good, after the user types its name. */
export async function deleteQuarantined(agentId: string, hostname: string, item: { id: string; path: string }): Promise<boolean> {
	const name = baseName(item.path);
	const ok = await confirmAction({
		title: `Delete ${name} permanently?`,
		message: `The agent on ${hostname} destroys its quarantined copy. It can’t be restored afterwards.`,
		confirmLabel: 'Delete permanently',
		danger: true,
		typeToConfirm: name
	});
	if (!ok) return false;
	return attempt(() => api.post(`/agents/${agentId}/security/respond`, { action: { type: 'delete_quarantined', id: item.id } }), `Delete sent to ${hostname}.`);
}
