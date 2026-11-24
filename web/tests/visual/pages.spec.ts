import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { expect, test, type Page, type WebSocketRoute } from '@playwright/test';
import { NOW, mockApi } from './mock';

const pages: [string, string][] = [
	['dashboard', '/'],
	['dashboard-client', '/?client=c-acme'],
	['agents', '/agents'],
	['agents-attention', '/agents?view=attention'],
	['agent', '/agents/a-3'],
	['agent-inventory', '/agents/a-3?tab=inventory'],
	['agent-software', '/agents/a-3?tab=software'],
	['agent-jobs', '/agents/a-3?tab=jobs'],
	['agent-activity', '/agents/a-1?tab=activity'],
	['agent-alerts', '/agents/a-3?tab=alerts'],
	['agent-services', '/agents/a-3?tab=services'],
	['agent-logs', '/agents/a-3?tab=logs'],
	['agent-processes', '/agents/a-3?tab=processes'],
	['agent-files', '/agents/a-3?tab=files&path=%2Fvar%2Flog'],
	['agent-alerts-snoozed', '/agents/a-4?tab=alerts'],
	['agent-desktop-unsupported', '/agents/a-6?tab=desktop'],
	['alerts', '/alerts'],
	['alert', '/alerts/al-5'],
	['policies', '/policies'],
	['policies-categories', '/policies?tab=categories'],
	['policies-assignments', '/policies?tab=assignments&client=c-acme'],
	['policy-set', '/policies/sets/ps-acme-win'],
	['policy-set-alert', '/policies/sets/ps-acme-win?section=alerts&item=p-disk'],
	['policy-set-alert-defined', '/policies/sets/00000000-0000-4000-8001-000000000000?section=alerts&item=p-svc'],
	['policy-set-patching', '/policies/sets/ps-acme-tills?section=patching'],
	['policy-set-security', '/policies/sets/00000000-0000-4000-8001-000000000000?section=security'],
	['policy-set-remote', '/policies/sets/ps-acme-tills?section=remote'],
	['policy-set-schedule', '/policies/sets/00000000-0000-4000-8001-000000000002?section=schedules&item=sc-1'],
	['policy-set-schedules-empty', '/policies/sets/ps-dc?section=schedules'],
	['policy-set-automations', '/policies/sets/00000000-0000-4000-8001-000000000000?section=automations'],
	['policy-set-automation-once', '/policies/sets/00000000-0000-4000-8001-000000000000?section=automations&item=au-addon'],
	['policy-set-automation-tag', '/policies/sets/00000000-0000-4000-8001-000000000000?section=automations&item=au-tag'],
	['policy-set-automation-field', '/policies/sets/00000000-0000-4000-8001-000000000000?section=automations&item=au-field'],
	['policy-set-automation-event', '/policies/sets/00000000-0000-4000-8001-000000000002?section=automations&item=au-disk'],
	['policy-set-automation-overridden', '/policies/sets/00000000-0000-4000-8001-000000000012?section=automations&item=au-addon'],
	['policy-new-automation', '/policies/sets/00000000-0000-4000-8001-000000000000?section=automations&item=new'],
	['policy-set-devices', '/policies/sets/ps-acme-win?section=devices'],
	['policy-set-children', '/policies/sets/00000000-0000-4000-8001-000000000012?section=children'],
	['policy-new', '/policies/sets/00000000-0000-4000-8001-000000000000?section=alerts&item=new'],
	['agent-policy', '/agents/a-3?tab=policy'],
	['agent-policy-assigned', '/agents/a-4?tab=policy'],
	['client-policies', '/clients/c-acme?tab=policies'],
	['schedules', '/schedules'],
	['schedule', '/schedules/sc-2'],
	['notifications', '/settings/notifications'],
	['agent-patches', '/agents/a-3?tab=patches'],
	['agent-deployments', '/agents/a-1?tab=deployments'],
	['policy-set-software', '/policies/sets/ps-acme-win?section=software'],
	['policy-set-software-item', '/policies/sets/ps-acme-win?section=software&item=sw-req'],
	['software', '/software'],
	['software-updates', '/software?tab=updates'],
	['software-history', '/software?tab=runs'],
	['software-package', '/software/sw-ff'],
	['software-run', '/software/runs/sr-2'],
	['agent-patches-windows', '/agents/a-1?tab=patches'],
	['security', '/security'],
	['security-detections', '/security?tab=detections&view=all'],
	['agent-security', '/agents/a-2?tab=security'],
	['agent-security-linux', '/agents/a-3?tab=security'],
	['agent-security-none', '/agents/a-5?tab=security'],
	['agent-security-sensor', '/agents/a-1?tab=security'],
	['agent-security-realtime', '/agents/a-6?tab=security'],
	['security-detection', '/security/detections/d-5'],
	['security-detection-file', '/security/detections/d-6'],
	['security-detection-denied', '/security/detections/d-8'],
	['security-quarantine', '/security?tab=quarantine&show=all'],
	['security-hunt', '/security?tab=hunt&sha256=9f2c4e1a7b3d5f60812a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d'],
	['security-rules', '/security?tab=rules'],
	['security-content', '/security?tab=content'],
	['security-settings', '/security?tab=settings'],
	['policy-new-security', '/policies/sets/00000000-0000-4000-8001-000000000000?section=alerts&item=new&kind=security'],
	['patches', '/patches'],
	['patches-update', '/patches?update=b3c1d2e4-0001'],
	['patches-compliance', '/patches?tab=compliance'],
	['patches-compliance-client', '/patches?tab=compliance&client=c-acme'],
	['patches-windows', '/patches?tab=windows'],
	['patches-history', '/patches?tab=history'],
	['patch-run', '/patches/runs/r-2'],
	['jobs', '/jobs'],
	['job', '/jobs/j-1'],
	['clients', '/clients'],
	['client', '/clients/c-acme'],
	['client-sites', '/clients/c-acme?tab=sites'],
	['client-settings', '/clients/c-acme?tab=settings'],
	['scripts', '/scripts'],
	['script', '/scripts/s-spool'],
	['audit', '/audit'],
	['settings', '/settings'],
	['users', '/settings/users'],
	['settings-sso', '/settings/sso'],
	['account', '/account'],
	['tickets', '/tickets'],
	['tickets-triage', '/tickets?view=triage'],
	['ticket', '/tickets/t-1'],
	['ticket-alert', '/tickets/t-2'],
	['client-tickets', '/clients/c-acme?tab=tickets'],
	['client-contacts', '/clients/c-acme?tab=contacts'],
	['client-docs', '/clients/c-acme?tab=docs&doc=d-network'],
	['client-docs-edit', '/clients/c-acme?tab=docs&doc=d-network&edit=1'],
	['client-passwords', '/clients/c-acme?tab=passwords'],
	['client-password', '/clients/c-acme?tab=passwords&item=6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111'],
	['client-password-managed', '/clients/c-acme?tab=passwords&item=6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a1f0'],
	['settings-documentation', '/settings/documentation'],
	['agent-tickets', '/agents/a-3?tab=tickets'],
	['agent-notes', '/agents/a-3?tab=notes'],
	['agents-tagged', '/agents?tag=tg-vip'],
	['client-fields', '/clients/c-acme?tab=fields'],
	['settings-fields', '/settings/fields'],
	['service-desk', '/settings/service-desk'],
	['settings-api', '/settings/api-keys'],
	['settings-webhooks', '/settings/webhooks'],
	['settings-siem', '/settings/siem'],
	['developers', '/developers'],
	['network', '/network'],
	['network-discovered', '/network?tab=discovered'],
	['network-discovered-all', '/network?tab=discovered&found=all'],
	['network-device', '/network/devices/nd-1?port=1'],
	['network-device-down', '/network/devices/nd-2'],
	['network-device-printer', '/network/devices/nd-3'],
	['network-settings', '/network/settings?client=c-acme']
];
const phone: [string, string][] = [
	['dashboard', '/'],
	['agents', '/agents'],
	['agent', '/agents/a-3'],
	['agent-notes', '/agents/a-3?tab=notes'],
	['settings-fields', '/settings/fields'],
	['job', '/jobs/j-1'],
	['alerts', '/alerts'],
	['patches', '/patches'],
	['agent-patches', '/agents/a-3?tab=patches'],
	['software', '/software'],
	['software-package', '/software/sw-ff'],
	['agent-deployments', '/agents/a-1?tab=deployments'],
	['security', '/security'],
	['agent-security', '/agents/a-2?tab=security'],
	['security-detection', '/security/detections/d-5'],
	['security-rules', '/security?tab=rules'],
	['security-content', '/security?tab=content'],
	['security-hunt', '/security?tab=hunt'],
	['agent-security-realtime', '/agents/a-6?tab=security'],
	['tickets', '/tickets'],
	['ticket', '/tickets/t-1'],
	['policies', '/policies'],
	['policy-set', '/policies/sets/ps-acme-win'],
	['policy-set-patching', '/policies/sets/ps-acme-tills?section=patching'],
	['policy-set-alert', '/policies/sets/ps-acme-win?section=alerts&item=p-disk'],
	['policy-set-automation-once', '/policies/sets/00000000-0000-4000-8001-000000000000?section=automations&item=au-addon'],
	['agent-policy', '/agents/a-3?tab=policy'],
	['client-policies', '/clients/c-acme?tab=policies'],
	['client-docs', '/clients/c-acme?tab=docs&doc=d-network'],
	['client-docs-edit', '/clients/c-acme?tab=docs&doc=d-network&edit=1'],
	['client-passwords', '/clients/c-acme?tab=passwords'],
	['settings-webhooks', '/settings/webhooks'],
	['settings-siem', '/settings/siem'],
	['network', '/network'],
	['network-device', '/network/devices/nd-1']
];

const jpeg = readFileSync(new URL('./fixtures/desktop.jpg', import.meta.url));

/** One remote desktop frame (desktop_ws.rs layout): the fixture as a single full-screen rect. */
function desktopFrame(seq: number) {
	const head = Buffer.alloc(23 + 13);
	let o = head.writeUInt8(1, 0);
	o = head.writeUInt32BE(seq, o);
	for (const v of [1920, 1080, 960, 540]) o = head.writeUInt16BE(v, o);
	o = head.writeInt32BE(1400, o); // remote cursor, screen pixels
	o = head.writeInt32BE(300, o);
	o = head.writeUInt16BE(1, o);
	for (const v of [0, 0, 960, 540]) o = head.writeUInt16BE(v, o);
	o = head.writeUInt8(1, o);
	head.writeUInt32BE(jpeg.length, o);
	return Buffer.concat([head, jpeg]);
}
const monitors = [
	{ name: 'DISPLAY1', x: 0, y: 0, width: 1920, height: 1080, primary: true },
	{ name: 'DISPLAY2', x: 1920, y: 0, width: 1280, height: 1024, primary: false }
];

/** Waits until nothing is loading: no skeletons, fonts in, lazy editors mounted. */
async function settle(page: Page) {
	// Every page has an h1 once the app has mounted; before that the page is empty.
	await page.locator('h1').first().waitFor({ timeout: 30_000 });
	// The gallery shows loading states on purpose.
	if (!page.url().includes('/dev/ui')) await expect(page.locator('[aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
	await page.evaluate(() => document.fonts.ready);
	if (await page.locator('#s-body, #rs-body, #doc-body').count()) await page.locator('.cm-editor').first().waitFor();
	await page.waitForTimeout(250);
}

for (const theme of ['light', 'dark'] as const) {
	test.describe(theme, () => {
		test.use({ colorScheme: theme });

		for (const [name, path] of pages) {
			test(name, async ({ page }) => {
				await mockApi(page);
				await page.goto(path);
				await settle(page);
				await expect(page).toHaveScreenshot(`${theme}-${name}.png`, { fullPage: true });
			});
		}

		test('gallery', async ({ page }) => {
			await mockApi(page, { signedIn: false });
			await page.goto('/dev/ui');
			await page.getByRole('heading', { name: 'UI gallery' }).waitFor();
			await settle(page);
			await expect(page).toHaveScreenshot(`${theme}-gallery.png`, { fullPage: true });
		});

		test('login', async ({ page }) => {
			await mockApi(page, { signedIn: false });
			await page.goto('/login');
			await settle(page);
			await expect(page).toHaveScreenshot(`${theme}-login.png`);
		});

		test('login with SSO required', async ({ page }) => {
			await mockApi(page, { signedIn: false, ssoRequired: true });
			await page.goto('/login?sso_error=not_allowed');
			await page.getByRole('link', { name: 'Sign in with Microsoft' }).waitFor();
			await settle(page);
			await expect(page).toHaveScreenshot(`${theme}-login-sso-required.png`);
			await page.getByRole('button', { name: /Use a password/ }).click();
			await expect(page.getByLabel('Password')).toBeVisible();
			const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
		});

		test('login second factor with a passkey', async ({ page }) => {
			await mockApi(page, { signedIn: false });
			await page.route('**/api/auth/login', (route) =>
				route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'two-factor code required', mfa_required: true, methods: { totp: true, passkey: true } }) })
			);
			await page.goto('/login');
			await page.getByLabel('Email').fill('dana@northwind.example');
			await page.getByLabel('Password').fill('correct horse battery');
			await page.getByRole('button', { name: 'Sign in', exact: true }).click();
			await page.getByRole('button', { name: 'Use a passkey' }).waitFor();
			await settle(page);
			await expect(page).toHaveScreenshot(`${theme}-login-passkey.png`);
			const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
		});

		test('SSO provider form and group mappings', async ({ page }) => {
			await mockApi(page);
			await page.goto('/settings/sso');
			await settle(page);
			await page.getByRole('button', { name: 'Add provider' }).click();
			await page.getByRole('dialog').getByLabel('Button label').fill('Contoso Entra');
			await page.getByRole('dialog').getByLabel('Tenant').fill('organizations');
			await page.getByRole('dialog').getByText('Allowed tenants').waitFor();
			await expect(page).toHaveScreenshot(`${theme}-sso-provider-form.png`);
			let r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
			await page.getByRole('button', { name: 'Cancel' }).click();
			await page.getByRole('button', { name: 'Group mappings for Microsoft' }).click();
			await page.getByRole('dialog').getByText('Clients and extra permissions').first().click();
			await expect(page.getByRole('dialog').getByLabel('Group').first()).toHaveValue('0b8d1f64-2e7a-4a53-9c1b-6f1d3a7e9c02');
			await expect(page).toHaveScreenshot(`${theme}-sso-mappings.png`);
			r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
		});

		test('run a script with parameters', async ({ page }) => {
			await mockApi(page);
			await page.goto('/agents/a-1');
			await settle(page);
			await page.getByRole('button', { name: 'Run script' }).first().click();
			const dialog = page.getByRole('dialog');
			await dialog.getByRole('combobox', { name: 'Script' }).click();
			await page.getByRole('option', { name: /Restart print spooler/ }).click();
			await dialog.getByLabel('Printer').fill('PRN-{{agent.hostname}}');
			await expect(dialog.getByText('$RMM_PARAM_ADMIN_PASSWORD')).toBeVisible();
			await expect(page).toHaveScreenshot(`${theme}-run-script-params.png`);
			const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
		});

		test('command palette', async ({ page }) => {
			await mockApi(page);
			await page.goto('/agents');
			await settle(page);
			await page.keyboard.press('Control+k');
			const input = page.getByPlaceholder(/Search agents, tickets, clients, sites/);
			await expect(input).toBeFocused();
			await input.fill('acme');
			await expect(page.getByRole('option', { name: /acme-dc01/ })).toBeVisible();
			await expect(page).toHaveScreenshot(`${theme}-palette.png`);
		});

		test('override an inherited field', async ({ page }) => {
			await mockApi(page);
			await page.goto('/policies/sets/ps-acme-win?section=patching');
			await settle(page);
			// Deferral comes from Acme's override; the restart setting is inherited from All devices.
			const reboot = page.locator('[data-source]').filter({ has: page.getByLabel('Restart after installing') });
			await expect(reboot).toHaveAttribute('data-source', 'overridden');
			const window = page.locator('[data-source]').filter({ has: page.getByRole('radio', { name: 'Its own' }) });
			await expect(window).toHaveAttribute('data-source', 'inherited');
			await expect(window.getByText('All devices')).toBeVisible();
			// Editing it makes it this set's override, field by field, before saving.
			await page.getByRole('radio', { name: 'Its own' }).click();
			await expect(window).toHaveAttribute('data-source', 'overridden');
			await expect(window.getByText('Changed')).toBeVisible();
			await expect(page.getByRole('status').filter({ hasText: 'Unsaved:' })).toContainText('Install window will be overridden in Acme · Windows servers');
			await expect(page).toHaveScreenshot(`${theme}-policy-set-override.png`);
			// Reset brings back the inherited value without saving anything else.
			await window.getByRole('button', { name: 'Reset Install window to inherited' }).click();
			await expect(window).toHaveAttribute('data-source', 'inherited');
			await expect(page.getByRole('status').filter({ hasText: 'Unsaved:' })).toHaveCount(0);
			const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
		});

		test('remote desktop', async ({ page }) => {
			await mockApi(page);
			const sent: Record<string, unknown>[] = [];
			let url = '';
			await page.routeWebSocket(/\/api\/agents\/[^/]+\/desktop/, (ws: WebSocketRoute) => {
				url = ws.url();
				ws.onMessage((m) => sent.push(JSON.parse(String(m))));
				ws.send(JSON.stringify({ type: 'info', monitors, monitor: 0 }));
				ws.send(desktopFrame(1));
			});
			await page.goto('/agents/a-3?tab=desktop');
			await settle(page);
			await expect(page.getByText('Connected', { exact: true })).toBeVisible();
			await expect.poll(() => sent).toContainEqual({ type: 'ack', seq: 1 });
			expect(url).toMatch(/quality=balanced&monitor=0$/);
			await expect(page.getByLabel('Monitor')).toBeVisible();

			// Input goes out in screen pixels (the frame is half the screen's size here).
			const screen = page.getByRole('application');
			const box = (await screen.boundingBox())!;
			await screen.click({ position: { x: box.width / 2, y: box.height / 2 } });
			await expect.poll(() => sent.flatMap((m) => (m.type === 'input' ? (m.events as Record<string, unknown>[]) : [])).find((e) => e.t === 'button' && e.down)).toMatchObject({ button: 'left', x: 960, y: 540 });
			await page.keyboard.press('KeyA');
			await expect.poll(() => sent.some((m) => m.type === 'input' && (m.events as { code?: string; down?: boolean }[]).some((e) => e.code === 'KeyA' && e.down === false))).toBe(true);
			await page.mouse.move(0, 0);

			await expect(page).toHaveScreenshot(`${theme}-agent-desktop.png`);
			const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
			expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
		});

		test('remote desktop waiting for consent', async ({ page }) => {
			await mockApi(page);
			await page.routeWebSocket(/\/api\/agents\/[^/]+\/desktop/, (ws: WebSocketRoute) => {
				ws.send(JSON.stringify({ type: 'waiting' }));
			});
			await page.goto('/agents/a-1?tab=desktop');
			await page.getByText('Waiting for the person at acme-dc01 to allow the session…').waitFor();
			await expect(page.getByText('Waiting for approval', { exact: true })).toBeVisible();
			await page.evaluate(() => document.fonts.ready);
			await expect(page).toHaveScreenshot(`${theme}-agent-desktop-waiting.png`);
		});

		test('rule mode menu', async ({ page }) => {
			await mockApi(page);
			await page.goto('/security?tab=rules');
			await settle(page);
			await page.getByRole('button', { name: 'Mode of RMM-B-0018' }).click();
			await expect(page.getByRole('menuitem', { name: /Block/ })).toHaveAttribute('aria-disabled', 'true');
			await expect(page.getByRole('menuitem', { name: /Block/ })).toHaveAttribute('title', /needs 7 days/);
			await expect(page).toHaveScreenshot(`${theme}-security-rule-menu.png`);
		});

		test('security policy in a set', async ({ page }) => {
			await mockApi(page);
			await page.goto('/policies/sets/ps-acme-web01?section=security');
			await settle(page);
			// Block from All devices, prevention switched off here: nothing is blocked, said plainly.
			await expect(page.getByText('Nothing will be blocked.')).toBeVisible();
			await expect(page.getByRole('radio', { name: 'Block' })).toHaveAttribute('aria-checked', 'true');
			await expect(page.getByLabel('Archive depth', { exact: true })).toHaveValue('3');
			const prevention = page.locator('[data-source]').filter({ has: page.getByRole('switch', { name: 'Prevention' }) });
			await expect(prevention).toHaveAttribute('data-source', 'overridden');
			await expect(page).toHaveScreenshot(`${theme}-policy-set-security-overridden.png`, { fullPage: true });
			// Turning prevention on makes Block real.
			await page.getByRole('switch', { name: 'Prevention' }).click();
			await expect(page.getByText('Nothing will be blocked.')).toHaveCount(0);
			await expect(page.getByText(/is denied before it runs/)).toBeVisible();
		});

		test('database rollback dialog', async ({ page }) => {
			await mockApi(page);
			await page.goto('/security?tab=content');
			await settle(page);
			await page.getByRole('region', { name: 'Signature databases' }).getByRole('button', { name: 'Roll back' }).nth(1).click();
			const dialog = page.getByRole('dialog', { name: 'Roll back 2026.06.14.2?' });
			await expect(dialog).toBeVisible();
			await expect(dialog.getByText(/Agents go back to 2026\.06\.10\.1/)).toBeVisible();
			await expect(page).toHaveScreenshot(`${theme}-security-database-rollback.png`);
		});

		test('kill process dialog', async ({ page }) => {
			await mockApi(page);
			await page.goto('/security/detections/d-5');
			await settle(page);
			await page.getByRole('button', { name: 'Kill process tree' }).click();
			const dialog = page.getByRole('dialog', { name: 'Kill a process on acme-fs01' });
			await expect(dialog).toBeVisible();
			await expect(dialog.getByLabel('Process ID')).toHaveValue('6120');
			await expect(page).toHaveScreenshot(`${theme}-security-kill-dialog.png`);
		});

		test('confirm dialog', async ({ page }) => {
			await mockApi(page);
			await page.goto('/clients/c-acme');
			await settle(page);
			await page.getByRole('button', { name: 'More actions' }).click();
			await page.getByRole('menuitem', { name: 'Delete client…' }).click();
			await expect(page.getByRole('alertdialog')).toBeVisible();
			await expect(page.getByRole('button', { name: 'Delete client' })).toBeDisabled();
			await page.getByLabel('Type Acme Corp to confirm').fill('Acme Corp');
			await expect(page.getByRole('button', { name: 'Delete client' })).toBeEnabled();
			await expect(page).toHaveScreenshot(`${theme}-confirm.png`);
		});

		test('fill a credential slot', async ({ page }) => {
			await mockApi(page);
			await page.goto('/clients/c-acme?tab=docs&doc=d-network&edit=1');
			await settle(page);
			const preview = page.getByRole('region', { name: 'Preview' });
			await preview.getByRole('button', { name: 'Choose credential' }).click();
			const dialog = page.getByRole('dialog', { name: 'Choose a credential' });
			await expect(dialog).toBeVisible();
			await dialog.getByText('Core switch').click();
			await expect(dialog.getByRole('radio', { name: /Core switch/ })).toBeChecked();
			await page.waitForTimeout(400);
			await expect(page).toHaveScreenshot(`${theme}-client-docs-pick.png`);
			await dialog.getByRole('button', { name: 'Link credential' }).click();
			await expect(dialog).toHaveCount(0);
			// The slot's block now names the item, so the preview shows its card.
			await expect(preview.getByRole('heading', { name: 'Core switch' })).toBeVisible();
			await expect(preview.getByRole('button', { name: 'Choose credential' })).toHaveCount(0);
			await expect(page.getByText('Unsaved changes')).toBeVisible();
			// Leaving asks first.
			await page.getByRole('button', { name: 'Cancel' }).first().click();
			await expect(page.getByRole('alertdialog')).toContainText('Discard changes?');
		});

		test('ticket documentation drawer', async ({ page }) => {
			await mockApi(page);
			await page.goto('/tickets/t-1');
			await settle(page);
			const card = page.getByRole('region', { name: 'Documentation' });
			await expect(card.getByRole('link')).toHaveText(['Network overview', 'Second-floor printer quirks']);
			await card.getByRole('link', { name: 'Network overview' }).click();
			const drawer = page.getByRole('dialog', { name: 'Documentation' });
			await expect(drawer.getByRole('heading', { name: 'Network overview', level: 2 })).toBeVisible();
			await expect(drawer.getByRole('link', { name: 'Open page' })).toHaveAttribute('href', '/clients/c-acme?tab=docs&doc=d-network');
			await expect(page).toHaveURL(/\/tickets\/t-1$/);
			await page.waitForTimeout(400);
			await expect(page).toHaveScreenshot(`${theme}-ticket-doc.png`);
		});

		test('credential card', async ({ page }) => {
			await mockApi(page);
			await page.goto('/clients/c-acme?tab=docs&doc=d-network');
			await settle(page);
			const card = page.locator('article').getByRole('region', { name: 'FortiGate admin' });
			await card.getByRole('button', { name: 'Reveal password' }).click();
			await expect(card.getByText('Tr0ub4dor&3-hx9Q')).toBeVisible();
			await card.getByRole('button', { name: 'Show code' }).click();
			await expect(card.getByText('492 039')).toBeVisible();
			await expect(card).toHaveScreenshot(`${theme}-credential-revealed.png`);
			// The chip of an inline link opens the same card in a popover.
			await page.getByRole('button', { name: 'Staff Wi-Fi key' }).last().click();
			await expect(page.getByRole('dialog', { name: 'Staff Wi-Fi key' })).toBeVisible();
		});

		test.describe('phone', () => {
			test.use({ viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true });
			for (const [name, path] of phone) {
				test(name, async ({ page }) => {
					await mockApi(page);
					await page.goto(path);
					await settle(page);
					await expect(page).toHaveScreenshot(`${theme}-phone-${name}.png`, { fullPage: true });
				});
			}
			test('navigation drawer', async ({ page }) => {
				await mockApi(page);
				await page.goto('/agents');
				await settle(page);
				await page.getByRole('button', { name: 'Open navigation' }).click();
				await expect(page.getByRole('dialog', { name: 'Navigation' })).toBeVisible();
				await expect(page).toHaveScreenshot(`${theme}-phone-drawer.png`);
			});
		});

		// WCAG 2.2 AA checks (contrast, names, roles) on every page, in this theme. One test per page,
		// so each has its own time budget and a failure names the page.
		for (const [name, path] of [...pages, ['gallery', '/dev/ui'] as [string, string]]) {
			test(`accessibility: ${name}`, async ({ page }) => {
				await mockApi(page);
				await page.goto(path);
				await settle(page);
				const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
				const problems = r.violations
					.filter((v) => v.impact === 'serious' || v.impact === 'critical')
					.map((v) => `${name}: ${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
				expect(problems, problems.join('\n')).toEqual([]);
			});
		}
	});
}

test('keyboard: g a, j/k and Enter', async ({ page }) => {
	await mockApi(page);
	await page.goto('/');
	await settle(page);
	await page.keyboard.press('g');
	await page.keyboard.press('a');
	await expect(page).toHaveURL(/\/agents$/);
	await settle(page);
	await page.keyboard.press('j');
	await page.keyboard.press('j');
	await page.keyboard.press('Enter');
	await expect(page).toHaveURL(/\/agents\/a-/);
	await page.keyboard.press('?');
	await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible();
});

// --- documentation and the vault: what the buttons do -------------------------------------------

type Call = { method: string; path: string; body: unknown };
/**
 * Answers some API calls differently from the shared mock (`fn` returns undefined to pass a call
 * on) and records every call that writes.
 */
async function routeApi(page: Page, fn: (method: string, path: string, body: unknown) => { status?: number; json: unknown } | undefined) {
	const calls: Call[] = [];
	await page.route('**/api/**', async (route) => {
		const req = route.request();
		const path = new URL(req.url()).pathname.replace(/^\/api/, '');
		const body = req.postData() ? req.postDataJSON() : null;
		if (req.method() !== 'GET') calls.push({ method: req.method(), path, body });
		const r = fn(req.method(), path, body);
		if (!r) return route.fallback();
		return route.fulfill({ status: r.status ?? 200, contentType: 'application/json', body: JSON.stringify(r.json) });
	});
	return calls;
}
const newDoc = (over: Record<string, unknown>) => ({
	id: 'd-new', client_id: 'c-acme', title: 'Untitled', category_id: null, category: '', body: '', updated_by_name: 'Dana Admin',
	updated_at: NOW.toISOString(), revisions: 0, history: [], credentials: [], credentials_hidden: false, tickets: [], ...over
});
/** The Markdown source: CodeMirror's content element, or the textarea before it loads. */
const editorText = (page: Page) => page.locator('#doc-body');

test.describe('documentation', () => {
	test('new page from a template', async ({ page }) => {
		await mockApi(page);
		let created: Record<string, unknown> | null = null;
		const calls = await routeApi(page, (method, path, body) => {
			if (method === 'GET' && path === '/doc-templates/00000000-0000-4000-8004-000000000002')
				return { json: { id: '00000000-0000-4000-8004-000000000002', name: 'Wi-Fi', category_id: '00000000-0000-4000-8003-000000000001', category: 'Network', description: '', body: '# Wi-Fi at {{client.name}}\n\nReviewed {{date}} by {{user.name}}.\n', updated_at: NOW.toISOString(), updated_by_name: null } };
			if (method === 'POST' && path === '/clients/c-acme/docs') {
				created = newDoc({ ...(body as object), category: 'Network' });
				return { json: { id: 'd-new' } };
			}
			if (method === 'GET' && path === '/docs/d-new' && created) return { json: created };
		});
		await page.goto('/clients/c-acme?tab=docs');
		await settle(page);
		await page.getByRole('button', { name: 'New page' }).first().click();
		const dialog = page.getByRole('dialog', { name: 'New page' });
		await dialog.getByText('SSIDs, the controller').click();
		await expect(dialog.getByLabel('Title')).toHaveValue('Wi-Fi');
		await dialog.getByLabel('Title').fill('Guest and staff Wi-Fi');
		await dialog.getByRole('button', { name: 'Open in the editor' }).click();
		await expect(dialog).toHaveCount(0);

		const editor = page.locator('section[aria-labelledby="doc-editor-h"]');
		await expect(page.getByRole('heading', { name: 'New page', level: 2 })).toBeVisible();
		await expect(page).toHaveURL(/edit=new/);
		await expect(editor.getByLabel('Title')).toHaveValue('Guest and staff Wi-Fi');
		await expect(editorText(page)).toContainText('# Wi-Fi at Acme Corp');
		await expect(editorText(page)).toContainText('Reviewed 2026-06-15 by Dana Admin.');
		await expect(page.getByRole('region', { name: 'Preview' }).getByRole('heading', { name: 'Wi-Fi at Acme Corp' })).toBeVisible();

		await editor.getByRole('button', { name: 'Save', exact: true }).click();
		await expect.poll(() => calls.filter((c) => c.method === 'POST')).toEqual([
			{ method: 'POST', path: '/clients/c-acme/docs', body: { title: 'Guest and staff Wi-Fi', category_id: '00000000-0000-4000-8003-000000000001', body: '# Wi-Fi at Acme Corp\n\nReviewed 2026-06-15 by Dana Admin.\n' } }
		]);
		await expect(page).toHaveURL(/doc=d-new/);
		await expect(page).not.toHaveURL(/edit=/);
		await expect(page.getByRole('heading', { name: 'Guest and staff Wi-Fi', level: 2 })).toBeVisible();
	});

	test('new page from an imported .md file', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, (method, path) => (method === 'POST' && path === '/clients/c-acme/docs' ? { json: { id: 'd-new' } } : undefined));
		await page.goto('/clients/c-acme?tab=docs');
		await settle(page);
		await page.getByRole('button', { name: 'New page' }).first().click();
		const dialog = page.getByRole('dialog', { name: 'New page' });
		await dialog.getByLabel('Import a Markdown file').setInputFiles({ name: 'vpn.md', mimeType: 'text/markdown', buffer: Buffer.from('---\ntitle: "Remote access VPN"\ncategory: Network\n---\n\n## Clients\n\nFortiClient 7.4.\n') });
		await expect(dialog).toHaveCount(0);
		await expect(page.getByRole('heading', { name: 'New page', level: 2 })).toBeVisible();
		await expect(page.locator('#doc-title-input')).toHaveValue('Remote access VPN');
		await expect(page.locator('#doc-category')).toHaveValue('00000000-0000-4000-8003-000000000001');
		await expect(editorText(page)).toContainText('FortiClient 7.4.');
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		await expect.poll(() => calls.find((c) => c.method === 'POST')?.body).toEqual({ title: 'Remote access VPN', category_id: '00000000-0000-4000-8003-000000000001', body: '## Clients\n\nFortiClient 7.4.\n' });
	});

	test('reload on a new draft goes back to the list', async ({ page }) => {
		await mockApi(page);
		await page.goto('/clients/c-acme?tab=docs&edit=new');
		await settle(page);
		await expect(page).not.toHaveURL(/edit=/);
		await expect(page.getByRole('heading', { name: 'Pages' })).toBeVisible();
	});

	test('leaving a new draft', async ({ page }) => {
		await mockApi(page);
		await page.goto('/clients/c-acme?tab=docs');
		await settle(page);
		const open = async (title: string) => {
			await page.getByRole('button', { name: 'New page' }).first().click();
			await page.getByRole('dialog', { name: 'New page' }).getByLabel('Title').fill(title);
			await page.getByRole('button', { name: 'Open in the editor' }).click();
			await expect(page.getByRole('heading', { name: 'New page', level: 2 })).toBeVisible();
		};
		// Back discards an untouched draft; Forward onto it finds none and drops the param.
		await open('Scratch');
		await page.goBack();
		await expect(page.getByRole('heading', { name: 'Pages' })).toBeVisible();
		await expect(page).not.toHaveURL(/edit=/);
		await page.goForward();
		await expect(page).not.toHaveURL(/edit=/);
		await expect(page.getByRole('heading', { name: 'Pages' })).toBeVisible();
		// With changes, leaving asks first, then goes where it was going.
		await open('Printers');
		await editorText(page).click();
		await page.keyboard.type('Two floors.');
		await expect(page.getByText('Unsaved changes')).toBeVisible();
		await page.getByRole('link', { name: /^Tickets/ }).first().click();
		await expect(page.getByRole('alertdialog')).toContainText('Discard changes?');
		await expect(page).toHaveURL(/edit=new/);
		await page.getByRole('alertdialog').getByRole('button', { name: 'Discard' }).click();
		await expect(page).toHaveURL(/\/tickets$/);
		await expect(page.getByRole('heading', { name: 'Tickets', level: 1 })).toBeVisible();
	});

	test('a stale save offers to overwrite', async ({ page }) => {
		await mockApi(page);
		let puts = 0;
		const calls = await routeApi(page, (method, path) => {
			if (method === 'PUT' && path === '/docs/d-change') return ++puts === 1 ? { status: 409, json: { error: 'someone else saved this page since you opened it' } } : { json: { ok: true, updated_at: NOW.toISOString() } };
		});
		await page.goto('/clients/c-acme?tab=docs&doc=d-change&edit=1');
		await settle(page);
		await page.locator('#doc-title-input').fill('Change window');
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		const banner = page.getByRole('alert').filter({ hasText: 'Someone else saved this page since you opened it.' });
		await expect(banner).toBeVisible();
		expect(calls[0].body).toMatchObject({ title: 'Change window', expected_updated_at: expect.any(String) });
		await expect(page).toHaveURL(/edit=1/);
		await banner.getByRole('button', { name: 'Save anyway' }).click();
		await expect(page).not.toHaveURL(/edit=/);
		expect(calls.length).toBe(2);
		expect(calls[1].body).toEqual({ title: 'Change window', category_id: '00000000-0000-4000-8003-000000000007', body: 'Sunday 22:00 to 02:00.' });
	});

	test('a stale save can be dropped', async ({ page }) => {
		await mockApi(page);
		await routeApi(page, (method, path) => (method === 'PUT' && path === '/docs/d-change' ? { status: 409, json: { error: 'conflict' } } : undefined));
		await page.goto('/clients/c-acme?tab=docs&doc=d-change&edit=1');
		await settle(page);
		await page.locator('#doc-title-input').fill('Change window');
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		await page.getByRole('button', { name: 'Discard mine' }).click();
		await expect(page).not.toHaveURL(/edit=/);
		await expect(page.getByRole('alertdialog')).toHaveCount(0);
		await expect(page.getByRole('heading', { name: 'Change procedure', level: 2 })).toBeVisible();
	});

	test('save a page as a template', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/clients/c-acme?tab=docs&doc=d-change');
		await settle(page);
		await page.getByRole('button', { name: 'More page actions' }).click();
		await page.getByRole('menuitem', { name: 'Save as template…' }).click();
		const dialog = page.getByRole('dialog', { name: 'Save as template' });
		await expect(dialog.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('Change procedure');
		await dialog.getByLabel('Description').fill('When changes may happen.');
		await dialog.getByRole('button', { name: 'Save template' }).click();
		await expect(dialog).toHaveCount(0);
		expect(calls).toEqual([{ method: 'POST', path: '/doc-templates', body: { name: 'Change procedure', description: 'When changes may happen.', category_id: '00000000-0000-4000-8003-000000000007', body: 'Sunday 22:00 to 02:00.' } }]);
		await expect(page.getByText('Template Change procedure saved.')).toBeVisible();
	});

	test('settings: templates and categories', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, (method, path, body) => {
			if (method === 'GET' && path === '/doc-templates/00000000-0000-4000-8004-000000000003')
				return { json: { id: '00000000-0000-4000-8004-000000000003', name: 'Server', category_id: '00000000-0000-4000-8003-000000000002', category: 'Infrastructure', description: 'One server.', body: '# {{client.name}} server\n', updated_at: NOW.toISOString(), updated_by_name: null } };
			if (method === 'POST' && path === '/doc-templates') return { json: { id: '00000000-0000-4000-8004-000000000099', ...(body as object), category: '', updated_at: NOW.toISOString(), updated_by_name: 'Dana Admin' } };
			if (method === 'PUT' && path.startsWith('/doc-templates/')) return { json: { id: path.split('/')[2], ...(body as object), category: '', updated_at: NOW.toISOString(), updated_by_name: 'Dana Admin' } };
			if (method === 'POST' && path === '/doc-categories') return { json: { id: '00000000-0000-4000-8003-000000000099', ...(body as object), position: 8, docs: 0, templates: 0 } };
		});
		await page.goto('/settings/documentation');
		await settle(page);

		// New template.
		await page.getByRole('link', { name: 'New template' }).click();
		await expect(page.getByRole('heading', { name: 'New template', level: 2 })).toBeVisible();
		await page.locator('#doc-title-input').fill('Printer');
		await page.locator('#doc-category').selectOption({ label: 'Infrastructure' });
		await page.locator('#doc-description').fill('A printer or copier.');
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		await expect(page).not.toHaveURL(/template=/);
		await expect(page.getByRole('heading', { name: 'Templates' })).toBeVisible();
		expect(calls.at(-1)).toMatchObject({ method: 'POST', path: '/doc-templates', body: { name: 'Printer', category_id: '00000000-0000-4000-8003-000000000002', description: 'A printer or copier.', body: expect.stringContaining('fields') } });

		// Edit one.
		await page.getByRole('link', { name: 'Edit Server' }).click();
		await expect(page.getByRole('heading', { name: 'Editing Server', level: 2 })).toBeVisible();
		await expect(page.locator('#doc-title-input')).toHaveValue('Server');
		await expect(editorText(page)).toContainText('{{client.name}} server');
		await page.locator('#doc-description').fill('One server, physical or virtual.');
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		await expect(page).not.toHaveURL(/template=/);
		expect(calls.at(-1)).toEqual({ method: 'PUT', path: '/doc-templates/00000000-0000-4000-8004-000000000003', body: { name: 'Server', category_id: '00000000-0000-4000-8003-000000000002', description: 'One server, physical or virtual.', body: '# {{client.name}} server\n' } });

		// Duplicate one.
		await page.getByRole('button', { name: 'Duplicate Server' }).click();
		await expect(page.getByText('Server (copy) added.')).toBeVisible();
		expect(calls.at(-1)).toEqual({ method: 'POST', path: '/doc-templates', body: { name: 'Server (copy)', category_id: '00000000-0000-4000-8003-000000000002', description: 'One server.', body: '# {{client.name}} server\n' } });

		// New category.
		await page.getByLabel('New category name').fill('Security');
		await page.getByRole('button', { name: 'Add', exact: true }).click();
		await expect(page.getByText('Security added.')).toBeVisible();
		await expect(page.getByLabel('New category name')).toHaveValue('');
		expect(calls.at(-1)).toEqual({ method: 'POST', path: '/doc-categories', body: { name: 'Security' } });
	});
});

test.describe('vault', () => {
	const fresh = {
		id: '5b4f7e7c-6a8d-4c2e-9f35-9c0d1e2f3a45', client_id: 'c-acme', name: 'NAS admin', username: 'root', url: 'https://10.0.0.20:5001', has_password: true, has_totp: false, has_notes: false,
		docs: 0, password_changed_at: NOW.toISOString(), updated_at: NOW.toISOString(), updated_by_name: 'Dana Admin', linked_docs: [], history: []
	};

	test('create a credential', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, (method, path) => {
			if (method === 'POST' && path === '/clients/c-acme/vault') return { json: fresh };
			if (method === 'GET' && path === `/vault/${fresh.id}`) return { json: fresh };
		});
		await page.goto('/clients/c-acme?tab=passwords');
		await settle(page);
		await page.getByRole('button', { name: 'New password' }).click();
		const dialog = page.getByRole('dialog', { name: 'New password' });
		await dialog.getByRole('textbox', { name: 'Name', exact: true }).fill('NAS admin');
		await dialog.getByLabel('Username').fill('root');
		await dialog.getByLabel('URL or host').fill('https://10.0.0.20:5001');
		await dialog.getByRole('textbox', { name: 'Password', exact: true }).fill('correct horse');
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(dialog).toHaveCount(0);
		expect(calls).toEqual([{ method: 'POST', path: '/clients/c-acme/vault', body: { name: 'NAS admin', username: 'root', url: 'https://10.0.0.20:5001', password: 'correct horse' } }]);
		await expect(page).toHaveURL(new RegExp(`item=${fresh.id}`));
		await expect(page.getByRole('dialog', { name: 'Credential' }).getByRole('heading', { name: 'NAS admin' })).toBeVisible();
	});

	test('edit a credential', async ({ page }) => {
		await mockApi(page);
		const fw = '6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111';
		const calls = await routeApi(page, (method, path, body) => {
			if (method === 'PUT' && path === `/vault/${fw}`) return { json: { ...fresh, id: fw, name: 'FortiGate admin', has_totp: true, ...(body as object) } };
		});
		await page.goto(`/clients/c-acme?tab=passwords&item=${fw}`);
		await settle(page);
		const drawer = page.getByRole('dialog', { name: 'Credential' });
		await drawer.getByRole('button', { name: 'Edit' }).click();
		const dialog = page.getByRole('dialog', { name: 'Edit FortiGate admin' });
		await expect(dialog.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('FortiGate admin');
		await expect(dialog.getByRole('textbox', { name: 'Password', exact: true })).toHaveAttribute('placeholder', 'Unchanged');
		await dialog.getByLabel('Username').fill('fgadmin');
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(dialog).toHaveCount(0);
		expect(calls).toEqual([{ method: 'PUT', path: `/vault/${fw}`, body: { name: 'FortiGate admin', username: 'fgadmin', url: 'https://10.0.0.1:4443' } }]);
		await expect(drawer).toBeVisible();
		await expect(drawer.getByText('fgadmin')).toBeVisible();
	});
});

test.describe('API keys and webhooks', () => {
	test('create an API key', async ({ page }) => {
		await mockApi(page);
		const token = `rmm_k_${'a1'.repeat(32)}`;
		const calls = await routeApi(page, (method, path) => {
			if (method === 'POST' && path === '/api-keys') return { json: { token, key: { ...{ id: 'k-9', name: 'Dashboard feed', prefix: token.slice(0, 12), owner_id: 'u-1', owner_name: 'Dana Admin', service_account: false, access: 'read', scopes: ['agents'], permissions: [], client_ids: ['c-acme'], rate_limit_per_min: 600, expires_at: null, last_used_at: null, last_used_ip: null, revoked_at: null, created_at: NOW.toISOString(), status: 'active' } } } };
		});
		await page.goto('/account');
		await settle(page);
		await page.getByRole('button', { name: 'Create key' }).click();
		const dialog = page.getByRole('dialog', { name: 'Create API key' });
		await expect(dialog.getByRole('button', { name: 'Create key' })).toBeDisabled();
		await dialog.getByLabel('Name').fill('Dashboard feed');
		await dialog.getByRole('checkbox', { name: 'Agents, inventory and metrics' }).click();
		await dialog.getByRole('switch', { name: 'Limit to some clients' }).click();
		await dialog.getByRole('checkbox', { name: 'Acme Corp' }).click();
		await dialog.getByLabel('Expires').selectOption('never');
		await dialog.getByRole('button', { name: 'Create key' }).click();
		expect(calls).toEqual([
			{ method: 'POST', path: '/api-keys', body: { name: 'Dashboard feed', access: 'read', scopes: ['agents'], permissions: [], client_ids: ['c-acme'], expires_in_days: null, rate_limit_per_min: 600 } }
		]);
		const shown = page.getByRole('dialog', { name: 'Copy your key now' });
		await expect(shown.getByText(token)).toBeVisible();
		await shown.getByRole('button', { name: 'I’ve copied it' }).click();
		await expect(shown).toHaveCount(0);
	});

	test('revoke an API key', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/account');
		await settle(page);
		await page.getByRole('button', { name: 'Revoke Reporting script' }).click();
		await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke key' }).click();
		await expect(page.getByText('Reporting script revoked.')).toBeVisible();
		expect(calls).toEqual([{ method: 'DELETE', path: '/api-keys/k-1', body: null }]);
	});

	test('add a webhook, see its secret and its log', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, (method, path) => {
			if (method === 'POST' && path === '/webhooks') return { json: { webhook: { id: 'wh-9' }, secret: 'whsec_0123456789abcdef' } };
		});
		await page.goto('/settings/webhooks');
		await settle(page);
		await page.getByRole('button', { name: 'Add webhook' }).click();
		const dialog = page.getByRole('dialog', { name: 'Add webhook' });
		await dialog.getByLabel('Name').fill('Status page');
		await dialog.getByLabel('URL').fill('https://status.example/hook');
		await dialog.getByRole('checkbox', { name: 'Alert acknowledged' }).click();
		await dialog.getByRole('button', { name: 'Save' }).click();
		expect(calls).toEqual([
			{
				method: 'POST',
				path: '/webhooks',
				body: { name: 'Status page', url: 'https://status.example/hook', events: ['ticket.created', 'ticket.updated', 'ticket.status_changed', 'ticket.resolved', 'ticket.comment', 'alert.created', 'alert.resolved'], client_id: null, internal_notes: false, enabled: true }
			}
		]);
		await expect(page.getByRole('dialog', { name: 'Signing secret for Status page' }).getByText('whsec_0123456789abcdef')).toBeVisible();
		await page.getByRole('button', { name: 'I’ve copied it' }).click();

		await page.getByRole('listitem').filter({ hasText: 'Acme dashboard' }).getByRole('button', { name: 'Log' }).click();
		const log = page.getByRole('dialog', { name: 'Deliveries to Acme dashboard' });
		await expect(log.getByText('HTTP 502', { exact: true })).toBeVisible();
		await expect(log.getByText('Retry 2')).toBeVisible();
		await log.getByRole('row').filter({ hasText: 'ticket.comment' }).getByRole('button', { name: 'Send again' }).click();
		expect(calls.at(-1)).toEqual({ method: 'POST', path: '/webhook-deliveries/8/redeliver', body: {} });
	});
});

test.describe('Audit export and SIEM', () => {
	test('the export links carry the filters', async ({ page }) => {
		await mockApi(page);
		await page.goto('/audit?action=user.&from=2026-11-01&to=2026-11-02');
		await settle(page);
		const csv = await page.getByRole('link', { name: 'Export CSV' }).getAttribute('href');
		const url = new URL(csv!, 'http://x');
		expect(url.pathname).toBe('/api/audit/export');
		expect(url.searchParams.get('action')).toBe('user.');
		expect(url.searchParams.get('format')).toBe('csv');
		expect(new Date(url.searchParams.get('from')!).getTime()).toBeLessThan(new Date(url.searchParams.get('to')!).getTime());
		expect(await page.getByRole('link', { name: 'Export JSON Lines' }).getAttribute('href')).toContain('format=jsonl');
	});

	test('add a destination and test another', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, (method, path) => {
			if (method === 'POST' && path === '/siem/destinations/sd-2/test') return { json: { ok: false, error: 'TLS handshake: invalid peer certificate: UnknownIssuer' } };
			if (method === 'POST' && path === '/siem/destinations') return { json: { id: 'sd-9' } };
		});
		await page.goto('/settings/siem');
		await settle(page);
		await expect(page.getByText('Failing (6)')).toBeVisible();
		await page.getByRole('listitem').filter({ hasText: 'Graylog (TLS)' }).getByRole('button', { name: 'Test' }).click();
		await expect(page.getByText(/UnknownIssuer/).first()).toBeVisible();

		await page.getByRole('button', { name: 'Add destination' }).click();
		const dialog = page.getByRole('dialog', { name: 'Add destination' });
		await dialog.getByLabel('Name').fill('Elastic');
		await dialog.getByLabel('Type').selectOption('https');
		await dialog.getByLabel('URL').fill('https://elastic.example/ingest');
		await dialog.getByLabel('Bearer token').fill('s3cret');
		await dialog.getByRole('checkbox', { name: 'Alerts' }).click();
		await dialog.getByRole('button', { name: 'Save' }).click();
		expect(calls.at(-1)).toEqual({
			method: 'POST',
			path: '/siem/destinations',
			body: {
				name: 'Elastic', kind: 'https', address: 'https://elastic.example/ingest', framing: 'octet', https_format: 'generic', facility: 13, ca_pem: '',
				send_audit: true, send_detections: false, send_alerts: true, enabled: true, token: 's3cret'
			}
		});
	});
});

test('filters live in the URL', async ({ page }) => {
	await mockApi(page);
	await page.goto('/agents');
	await settle(page);
	await page.getByRole('tab', { name: /^Offline/ }).click();
	await expect(page).toHaveURL(/view=offline/);
	await page.getByRole('button', { name: 'Hostname' }).click();
	await expect(page).toHaveURL(/sort=hostname&dir=desc|dir=desc/);
	await page.reload();
	await expect(page.getByRole('tab', { name: /^Offline/ })).toHaveAttribute('aria-selected', 'true');
});

test.describe('tags, fields, notes and saved views', () => {
	test('choosing a saved view goes to its URL and sets its columns', async ({ page }) => {
		await mockApi(page);
		await page.goto('/agents');
		await settle(page);
		await page.getByRole('button', { name: /Views/ }).click();
		await page.getByRole('menuitem', { name: /VIP machines/ }).click();
		await expect(page).toHaveURL(/tag=tg-vip/);
		await expect(page.getByRole('row', { name: /acme-dc01/ })).toBeVisible();
		await expect(page.getByRole('row', { name: /globex/ })).toHaveCount(0);
		// The view that matches the URL is named on the button.
		await expect(page.getByRole('button', { name: /VIP machines/ })).toBeVisible();
	});

	test('save the current view', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/agents?os=windows&sort=hostname&dir=desc&after=abc');
		await settle(page);
		await page.getByRole('button', { name: /Views/ }).click();
		await page.getByRole('menuitem', { name: /Save this view/ }).click();
		const dialog = page.getByRole('dialog', { name: 'Save this view' });
		await dialog.getByLabel('Name').fill('Windows, Z to A');
		await dialog.getByRole('switch', { name: /Share with everyone/ }).click();
		await dialog.getByRole('button', { name: 'Save view' }).click();
		// Paging cursors never become part of a view.
		expect(calls[0]).toMatchObject({ method: 'POST', path: '/saved-views', body: { page: 'agents', name: 'Windows, Z to A', query: 'os=windows&sort=hostname&dir=desc', shared: true } });
	});

	test('tag several agents at once', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/agents');
		await settle(page);
		await page.getByRole('checkbox', { name: /Select all/ }).click();
		await page.getByRole('button', { name: 'Tags', exact: true }).click();
		const dialog = page.getByRole('dialog', { name: 'Change tags' });
		await dialog.getByLabel('What to do with Pilot ring').selectOption('add');
		await dialog.getByLabel('What to do with Legacy').selectOption('remove');
		await dialog.getByRole('button', { name: 'Apply' }).click();
		expect(calls.at(-1)).toMatchObject({ method: 'POST', path: '/agents/tags', body: { add: ['tg-pilot'], remove: ['tg-legacy'] } });
	});

	test('add and pin a note', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/agents/a-3?tab=notes');
		await settle(page);
		await expect(page.getByRole('complementary', { name: 'Pinned note' })).toContainText('Reboots itself every Sunday night');
		await page.getByLabel('Add a note').fill('Swapped the PSU <b>today</b>');
		await page.getByRole('button', { name: 'Add note' }).click();
		expect(calls).toEqual([{ method: 'POST', path: '/agents/a-3/notes', body: { body: 'Swapped the PSU <b>today</b>', pinned: false } }]);
		// Someone else's note can be pinned but not edited.
		await expect(page.getByRole('button', { name: 'Edit note' })).toHaveCount(1);
	});

	test('edit custom fields on an agent', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/agents/a-3');
		await settle(page);
		await page.getByRole('region', { name: 'Custom fields' }).getByRole('button', { name: 'Edit' }).click();
		await page.getByLabel('Support tier').selectOption('Silver');
		await page.getByLabel('Owner').fill('');
		await page.getByRole('button', { name: 'Save' }).click();
		// Only what changed is sent; clearing is null.
		expect(calls).toEqual([{ method: 'PUT', path: '/agents/a-3/fields', body: { values: { support_tier: 'Silver', owner: null } } }]);
	});

	test('define a field that scripts may set', async ({ page }) => {
		await mockApi(page);
		const calls = await routeApi(page, () => undefined);
		await page.goto('/settings/fields');
		await settle(page);
		await page.getByRole('button', { name: 'Add field' }).click();
		const dialog = page.getByRole('dialog', { name: 'New custom field' });
		await dialog.getByLabel('Label').fill('Last backup');
		await expect(dialog.getByLabel('Name')).toHaveValue('last_backup');
		await dialog.getByLabel('Type').selectOption('date');
		await dialog.getByRole('switch', { name: 'Scripts can set it' }).click();
		await expect(dialog.getByText('RMM-FIELD last_backup=value')).toBeVisible();
		await dialog.getByRole('button', { name: 'Save' }).click();
		expect(calls).toEqual([
			{ method: 'POST', path: '/custom-fields', body: { entity: 'agent', name: 'last_backup', label: 'Last backup', description: '', kind: 'date', options: [], client_id: null, script_writable: true } }
		]);
	});
});
