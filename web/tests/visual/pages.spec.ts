import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { expect, test, type Page, type WebSocketRoute } from '@playwright/test';
import { mockApi } from './mock';

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
	['account', '/account'],
	['tickets', '/tickets'],
	['tickets-triage', '/tickets?view=triage'],
	['ticket', '/tickets/t-1'],
	['ticket-alert', '/tickets/t-2'],
	['client-tickets', '/clients/c-acme?tab=tickets'],
	['client-contacts', '/clients/c-acme?tab=contacts'],
	['agent-tickets', '/agents/a-3?tab=tickets'],
	['service-desk', '/settings/service-desk']
];
const phone: [string, string][] = [
	['dashboard', '/'],
	['agents', '/agents'],
	['agent', '/agents/a-3'],
	['job', '/jobs/j-1'],
	['alerts', '/alerts'],
	['patches', '/patches'],
	['agent-patches', '/agents/a-3?tab=patches'],
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
	['agent-policy', '/agents/a-3?tab=policy'],
	['client-policies', '/clients/c-acme?tab=policies']
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
	if (await page.locator('#s-body, #rs-body').count()) await page.locator('.cm-editor').first().waitFor();
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

		// WCAG 2.2 AA checks (contrast, names, roles) on every page, in this theme.
		test('accessibility', async ({ page }) => {
			test.setTimeout(420_000);
			await mockApi(page);
			const problems: string[] = [];
			for (const [name, path] of [...pages, ['gallery', '/dev/ui'] as [string, string]]) {
				await page.goto(path);
				await settle(page);
				const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
				for (const v of r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')) {
					problems.push(`${name}: ${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
				}
			}
			expect(problems, problems.join('\n')).toEqual([]);
		});
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
